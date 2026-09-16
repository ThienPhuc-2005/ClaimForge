import type { ActorId, CapturedRequest, FindingConfidence } from "./types.ts";
import { headerValue, headerValues, parseCookieHeader, parseSetCookie } from "./cookies.ts";
import { DEFAULT_POLICY, isSuccessStatus, type AnalysisPolicy } from "./policy.ts";
import { isLabOrigin } from "./session.ts";
import type { ReasonCode } from "./evidence.ts";

/**
 * Refresh-token rotation abuse (OWASP A07 / CWE-613). A rotating server issues a
 * new refresh token on every refresh and should reject the old one. If a token
 * that was rotated away is accepted again (2xx), rotation may not be enforced.
 *
 * This is never Confirmed from a passive capture: a short reuse/leeway window is
 * an explicitly allowed pattern (RFC 9700; major IdPs ship a "reuse interval"),
 * so a single replay can be legitimate. Hits are Suspicion — a candidate to
 * verify in a lab, not a proven bug.
 *
 * Detection is scoped to real token/refresh endpoints so a benign cookie whose
 * name merely contains "refresh" (e.g. csrf-refresh-token) never trips it.
 */

const TOKEN = "[A-Za-z0-9._~+/=-]{8,512}";
// snake_case and camelCase, hyphenated too.
const PRESENTED_RE = new RegExp(`refresh[_-]?token["']?\\s*[:=]\\s*["']?(${TOKEN})`, "gi");
const QUERY_RE = new RegExp(`[?&]refresh[_-]?token=(${TOKEN})`, "gi");
const ISSUED_RE = new RegExp(`"refresh[_-]?token"\\s*:\\s*"(${TOKEN})"`, "i");
const REFRESH_COOKIE = /^(refresh|refresh[_-]?token|refreshtoken)$/i;
const REFRESH_HEADER = /^x-refresh[_-]?token$/i;
const TOKEN_ENDPOINT = /(\/oauth2?\/token|\/token(\/|$)|\/refresh|\/auth\/(refresh|token)|\/sessions?\/refresh)/i;

function uniq(xs: string[]): string[] {
  return [...new Set(xs.filter(Boolean))];
}

export function refreshTokenPresented(req: CapturedRequest): string[] {
  const out: string[] = [];
  const body = req.requestBody ?? "";
  for (const m of body.matchAll(PRESENTED_RE)) out.push(m[1]!);
  for (const m of req.url.matchAll(QUERY_RE)) {
    try {
      out.push(decodeURIComponent(m[1]!));
    } catch {
      out.push(m[1]!);
    }
  }
  const cookie = headerValue(req.requestHeaders, "cookie");
  if (cookie) {
    for (const c of parseCookieHeader(cookie, req.actor)) {
      if (REFRESH_COOKIE.test(c.name) && c.value.length >= 8) out.push(c.value);
    }
  }
  for (const h of req.requestHeaders) {
    if (REFRESH_HEADER.test(h.name.trim()) && h.value.trim().length >= 8) out.push(h.value.trim());
  }
  return uniq(out);
}

export function refreshTokenIssued(req: CapturedRequest): string | undefined {
  const body = req.responseBody ?? "";
  const m = ISSUED_RE.exec(body);
  if (m) return m[1];
  for (const sc of headerValues(req.responseHeaders, "set-cookie")) {
    for (const rec of parseSetCookie(sc, req.actor)) {
      if (REFRESH_COOKIE.test(rec.name) && rec.value.length >= 8) return rec.value;
    }
  }
  return undefined;
}

export function isRefreshRequest(req: CapturedRequest): boolean {
  if (req.method === "PASTE" || req.method === "OPTIONS") return false;
  const blob = `${req.requestBody ?? ""} ${req.url}`;
  if (/grant_type=refresh_token/i.test(blob)) return true;
  // Otherwise require a real token/refresh endpoint before trusting the tokens,
  // so a "refresh"-named cookie on an ordinary page is not treated as a refresh.
  if (!TOKEN_ENDPOINT.test(req.path)) return false;
  return refreshTokenPresented(req).length > 0 || Boolean(refreshTokenIssued(req));
}

export interface RefreshHit {
  actor: ActorId;
  method: string;
  template: string;
  path: string;
  status: number;
  tokenHint: string;
  origin: string;
  lab: boolean;
  rotationObserved: boolean;
  confidence: FindingConfidence;
  reasonCodes: ReasonCode[];
}

function hint(v: string): string {
  return v.length <= 8 ? "••••" : `${v.slice(0, 4)}…`;
}

export function refreshTokenReuse(
  requests: CapturedRequest[],
  policy: AnalysisPolicy = DEFAULT_POLICY,
): RefreshHit[] {
  const events = requests
    .filter((r) => r.method !== "PASTE")
    .filter(isRefreshRequest)
    .sort((a, b) => a.startedAt - b.startedAt);

  const rotatedAway = new Set<string>(); // tokens the server replaced with a different one
  const presentedBefore = new Map<string, string>(); // token -> reqId that first presented it (2xx)
  const hits: RefreshHit[] = [];
  const seen = new Set<string>();

  for (const req of events) {
    const presented = refreshTokenPresented(req);
    const issued = refreshTokenIssued(req);
    const ok = isSuccessStatus(req.status, policy);

    for (const tok of presented) {
      if (!ok) continue;
      const reuseKey = `${req.actor}:${tok}:${req.id}`;
      if (seen.has(reuseKey)) continue;

      if (rotatedAway.has(tok)) {
        seen.add(reuseKey);
        hits.push({
          actor: req.actor,
          method: req.method,
          template: req.template,
          path: req.path,
          status: req.status,
          tokenHint: hint(tok),
          origin: req.origin,
          lab: isLabOrigin(req.origin),
          rotationObserved: true,
          // Never Confirmed: a short reuse/leeway window is a legitimate pattern.
          confidence: "suspicion",
          reasonCodes: ["REFRESH_TOKEN_REUSE", "REFRESH_ROTATION_OBSERVED", "IMPACT_NOT_PROVEN"],
        });
      } else if (presentedBefore.has(tok) && presentedBefore.get(tok) !== req.id) {
        seen.add(reuseKey);
        hits.push({
          actor: req.actor,
          method: req.method,
          template: req.template,
          path: req.path,
          status: req.status,
          tokenHint: hint(tok),
          origin: req.origin,
          lab: isLabOrigin(req.origin),
          rotationObserved: false,
          confidence: "suspicion",
          reasonCodes: ["REFRESH_TOKEN_REPLAYED", "IMPACT_NOT_PROVEN"],
        });
      }
      if (!presentedBefore.has(tok)) presentedBefore.set(tok, req.id);
    }

    // Rotation: this event handed back a *different* refresh token than it was given.
    if (issued) {
      for (const tok of presented) {
        if (tok !== issued) rotatedAway.add(tok);
      }
    }
  }
  return hits;
}
