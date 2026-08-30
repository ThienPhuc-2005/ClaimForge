import type { ActorId, CapturedRequest, FindingConfidence, TimelineEvent } from "./types.ts";
import { headerValue, parseCookieHeader } from "./cookies.ts";
import { bearerOf } from "./loot.ts";
import { DEFAULT_POLICY, pathMatches, routeClass, type AnalysisPolicy } from "./policy.ts";
import { isCredentialHeader } from "./replay-credentials.ts";
import type { ReasonCode } from "./evidence.ts";

const SESSION_COOKIE = /^(sid|session|sessionid|jsessionid|phpsessid|auth|token|jwt|refresh|access|connect\.sid)$/i;
const SKIP_COOKIE = /^(theme|locale|lang|tz|timezone|cookieconsent|optanon)/i;

function looksLogoutPath(path: string, policy: AnalysisPolicy): boolean {
  return pathMatches(path, policy.logoutPathPatterns);
}

function pathKind(req: CapturedRequest, policy: AnalysisPolicy = DEFAULT_POLICY): TimelineEvent["kind"] {
  const p = req.path.toLowerCase();
  const body = `${req.requestBody ?? ""}${req.url}`;
  if (looksLogoutPath(req.path, policy) && req.method !== "OPTIONS") return "logout";
  if (/refresh/.test(p) || /grant_type=refresh_token/i.test(body)) return "refresh";
  if (
    req.method !== "GET" &&
    req.method !== "OPTIONS" &&
    (/\/(login|signin|sign-in|oauth\/token|session)\b/.test(p) || /grant_type=password/i.test(body))
  ) {
    return "login";
  }
  if (req.status === 401 || req.status === 403) return "error";
  if (headerValue(req.requestHeaders, "authorization") || headerValue(req.requestHeaders, "cookie")) return "authz";
  return "traffic";
}

export function classifyTimeline(req: CapturedRequest, policy: AnalysisPolicy = DEFAULT_POLICY): { kind: TimelineEvent["kind"]; label: string } {
  const kind = pathKind(req, policy);
  if (kind === "login") return { kind, label: `Login ${req.path}` };
  if (kind === "refresh") return { kind, label: `Refresh ${req.path}` };
  if (kind === "logout") return { kind, label: `Logout ${req.path}` };
  if (kind === "error") return { kind, label: `${req.status} ${req.template}` };
  if (kind === "authz") return { kind, label: `${req.method} ${req.template} → ${req.status || "—"}` };
  return { kind, label: `${req.method} ${req.template}` };
}

export interface SessionCredential {
  kind: "bearer" | "cookie" | "api-key" | "header";
  id: string;
  hint: string;
}

export interface AliveAfterLogout {
  actor: ActorId;
  path: string;
  method: string;
  status: number;
  tokenHint: string;
  credentialId: string;
  origin: string;
  lab: boolean;
  logoutOk: boolean;
  confidence: FindingConfidence;
  reasonCodes: ReasonCode[];
  credentialKind: SessionCredential["kind"];
}

export function isLabOrigin(origin: string): boolean {
  if (!origin) return false;
  try {
    const h = new URL(origin).hostname.toLowerCase();
    return (
      h === "shop.lab" ||
      h === "lab.local" ||
      h.endsWith(".lab") ||
      h === "localhost" ||
      h === "127.0.0.1"
    );
  } catch {
    return /\.lab$/.test(origin);
  }
}

function hintOf(value: string): string {
  const v = value.trim();
  if (v.length <= 8) return "••••";
  return `${v.slice(0, 4)}…`;
}

export function credentialsOn(req: CapturedRequest): SessionCredential[] {
  const out: SessionCredential[] = [];
  const seen = new Set<string>();
  const add = (c: SessionCredential) => {
    if (seen.has(c.id) || !c.id) return;
    seen.add(c.id);
    out.push(c);
  };
  const bearer = bearerOf(req);
  if (bearer) add({ kind: "bearer", id: `bearer:${bearer}`, hint: hintOf(bearer) });
  const cookie = headerValue(req.requestHeaders, "cookie");
  if (cookie) {
    for (const rec of parseCookieHeader(cookie, req.actor)) {
      if (SKIP_COOKIE.test(rec.name)) continue;
      if (!SESSION_COOKIE.test(rec.name) && rec.value.length < 8) continue;
      add({ kind: "cookie", id: `cookie:${rec.name}=${rec.value}`, hint: `${rec.name}=${hintOf(rec.value)}` });
    }
  }
  for (const h of req.requestHeaders) {
    const n = h.name.toLowerCase();
    if (n === "authorization" || n === "cookie") continue;
    if (!isCredentialHeader(h.name) || !h.value.trim()) continue;
    const kind = /api-?key/i.test(h.name) ? "api-key" : "header";
    add({ kind, id: `${n}:${h.value}`, hint: `${h.name} ${hintOf(h.value)}` });
  }
  return out;
}

/** Logout analysis target: policy logout route, not public, not OPTIONS, and either mutating or credentialed. */
export function isLogoutAnalysisTarget(req: CapturedRequest, policy: AnalysisPolicy = DEFAULT_POLICY): boolean {
  if (req.method === "OPTIONS" || req.method === "PASTE") return false;
  if (!looksLogoutPath(req.path, policy)) return false;
  if (routeClass(req.path, policy) === "public") return false;
  const mutating = /^(POST|PUT|PATCH|DELETE)$/i.test(req.method);
  if (mutating) return true;
  return credentialsOn(req).length > 0;
}

export function sessionCredential(req: CapturedRequest): string | undefined {
  return credentialsOn(req)[0]?.id;
}

interface RevokeMeta {
  logoutOk: boolean;
  origin: string;
  actor: ActorId;
}

/**
 * Only credentials present on the logout request are revoked.
 * Sibling sessions (other bearer/cookie pairs) stay live.
 * Confirmed only in-lab when logout itself was 2xx.
 * Public logout-named routes and unauthenticated logout are not Confirmed.
 */
export function tokensAliveAfterLogout(
  requests: CapturedRequest[],
  policy: AnalysisPolicy = DEFAULT_POLICY,
): AliveAfterLogout[] {
  const sorted = [...requests].filter((r) => r.method !== "PASTE").sort((a, b) => a.startedAt - b.startedAt);
  const revoked = new Map<string, RevokeMeta>();
  const hits: AliveAfterLogout[] = [];
  const seenHit = new Set<string>();

  for (const req of sorted) {
    const kind = pathKind(req, policy);
    if (kind === "logout" && isLogoutAnalysisTarget(req, policy)) {
      const logoutOk = req.status >= 200 && req.status < 300;
      const onReq = credentialsOn(req);
      for (const c of onReq) {
        revoked.set(c.id, { logoutOk, origin: req.origin, actor: req.actor });
      }
      continue;
    }
    if (kind === "logout") continue;
    if (req.status < 200 || req.status >= 300) continue;
    if (routeClass(req.path, policy) === "public") continue;

    for (const c of credentialsOn(req)) {
      const meta = revoked.get(c.id);
      if (!meta) continue;
      const lab = isLabOrigin(req.origin) || isLabOrigin(meta.origin);
      const confidence: FindingConfidence = lab && meta.logoutOk ? "confirmed" : "suspicion";
      const key = `${req.actor}:${c.id}:${req.method}:${req.path}`;
      if (seenHit.has(key)) continue;
      seenHit.add(key);
      hits.push({
        actor: req.actor,
        path: req.path,
        method: req.method,
        status: req.status,
        tokenHint: c.hint,
        credentialId: c.id,
        origin: req.origin,
        lab,
        logoutOk: meta.logoutOk,
        confidence,
        reasonCodes: ["LOGOUT_CREDENTIAL_REPLAYED"],
        credentialKind: c.kind,
      });
    }
  }
  return hits;
}
