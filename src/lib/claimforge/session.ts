import type { CapturedRequest, TimelineEvent } from "./types.ts";
import { headerValue } from "./cookies.ts";
import { bearerOf } from "./loot.ts";

function pathKind(req: CapturedRequest): TimelineEvent["kind"] {
  const p = req.path.toLowerCase();
  const body = `${req.requestBody ?? ""}${req.url}`;
  if (/logout|signout|revoke|sign-off/.test(p) && req.method !== "OPTIONS") return "logout";
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

export function classifyTimeline(req: CapturedRequest): { kind: TimelineEvent["kind"]; label: string } {
  const kind = pathKind(req);
  if (kind === "login") return { kind, label: `Login ${req.path}` };
  if (kind === "refresh") return { kind, label: `Refresh ${req.path}` };
  if (kind === "logout") return { kind, label: `Logout ${req.path}` };
  if (kind === "error") return { kind, label: `${req.status} ${req.template}` };
  if (kind === "authz") return { kind, label: `${req.method} ${req.template} → ${req.status || "—"}` };
  return { kind, label: `${req.method} ${req.template}` };
}

export interface AliveAfterLogout {
  actor: CapturedRequest["actor"];
  path: string;
  method: string;
  status: number;
  tokenHint: string;
}

export function sessionCredential(req: CapturedRequest): string | undefined {
  return bearerOf(req) ?? headerValue(req.requestHeaders, "cookie");
}

/** Same bearer/cookie still 2xx after that actor logged out. */
export function tokensAliveAfterLogout(requests: CapturedRequest[]): AliveAfterLogout[] {
  const sorted = [...requests].filter((r) => r.method !== "PASTE").sort((a, b) => a.startedAt - b.startedAt);
  const live = new Map<string, Set<string>>();
  const revoked = new Set<string>();
  const hits: AliveAfterLogout[] = [];
  for (const req of sorted) {
    const tok = sessionCredential(req);
    const kind = pathKind(req);
    if (tok) {
      const set = live.get(req.actor) ?? new Set<string>();
      set.add(tok);
      live.set(req.actor, set);
    }
    if (kind === "logout") {
      for (const t of live.get(req.actor) ?? []) revoked.add(t);
      continue;
    }
    if (!tok || !revoked.has(tok)) continue;
    if (req.status < 200 || req.status >= 300) continue;
    hits.push({
      actor: req.actor,
      path: req.path,
      method: req.method,
      status: req.status,
      tokenHint: tok.slice(0, 12) + "…",
    });
  }
  return hits;
}
