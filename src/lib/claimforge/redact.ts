import type { CookieRecord, JwtToken, ReplayItem, Workspace } from "./types.ts";
import { extractJwtStrings } from "./jwt.ts";

export function maskSecret(value: string): string {
  if (!value) return value;
  if (value.length <= 8) return "••••";
  return `${value.slice(0, 4)}…${value.slice(-3)}`;
}

export function redactJwt(raw: string): string {
  const segs = raw.split(".");
  if (segs.length < 2) return maskSecret(raw);
  if (segs.length >= 3 && segs[2]) return `${segs[0]}.${segs[1]}.[sig]`;
  return `${segs[0]}.${segs[1]}.`;
}

export function redactText(input: string): string {
  let out = input;
  for (const t of extractJwtStrings(out)) out = out.split(t).join(redactJwt(t));
  out = out.replace(/Bearer\s+\S+/gi, "Bearer [redacted]");
  out = out.replace(/Basic\s+\S+/gi, "Basic [redacted]");
  out = out.replace(/([?&](?:access_token|token|jwt|refresh_token)=)[^&\s]+/gi, "$1[redacted]");
  out = out.replace(/((?:api[_-]?key|x-api-key|client_secret|password)\s*[:=]\s*)("[^"]*"|'[^']*'|\S+)/gi, "$1[redacted]");
  return out;
}

export function redactCookie(c: CookieRecord): CookieRecord {
  return { ...c, value: maskSecret(c.value) };
}

export function redactJwtToken(j: JwtToken): JwtToken {
  return { ...j, raw: redactJwt(j.raw), signature: j.signature ? "[sig]" : "" };
}

export function redactReplay(r: ReplayItem): ReplayItem {
  return { ...r, curl: redactText(r.curl), raw: redactText(r.raw) };
}

export function redactWorkspace(ws: Workspace): Workspace {
  return {
    ...ws,
    aRaw: "",
    bRaw: "",
    requests: ws.requests.map((r) => ({
      ...r,
      url: redactText(r.url),
      requestHeaders: r.requestHeaders.map((h) =>
        /authorization|cookie|api-?key|secret|token/i.test(h.name) ? { ...h, value: "[redacted]" } : h,
      ),
      responseHeaders: r.responseHeaders.map((h) =>
        /set-cookie|authorization|api-?key/i.test(h.name) ? { ...h, value: "[redacted]" } : h,
      ),
      requestBody: r.requestBody ? redactText(r.requestBody) : r.requestBody,
      responseBody: r.responseBody ? redactText(r.responseBody) : r.responseBody,
    })),
    jwts: ws.jwts.map(redactJwtToken),
    cookies: ws.cookies.map(redactCookie),
    loot: ws.loot.map((l) =>
      l.kind === "secret" || l.kind === "key" ? { ...l, value: maskSecret(l.value) } : l,
    ),
    replays: ws.replays.map(redactReplay),
    timeline: ws.timeline.map((t) => ({ ...t, detail: redactText(t.detail) })),
  };
}
