import type { CapturedRequest, CookieRecord, Finding, JwtToken, ReplayItem, Workspace } from "./types.ts";
import { extractJwtStrings } from "./jwt.ts";

export function maskSecret(value: string): string {
  if (!value) return value;
  if (value.length <= 8) return "••••";
  return `${value.slice(0, 4)}…${value.slice(-3)}`;
}

export function redactJwt(raw: string): string {
  const segs = raw.split(".");
  if (segs.length < 2) return maskSecret(raw);
  return `${segs[0]}.[payload].[sig]`;
}

export function redactText(input: string): string {
  let out = input;
  for (const t of extractJwtStrings(out)) out = out.split(t).join(redactJwt(t));
  out = out.replace(/Bearer\s+\S+/gi, "Bearer [redacted]");
  out = out.replace(/Basic\s+\S+/gi, "Basic [redacted]");
  out = out.replace(/((?:Set-)?Cookie:\s*)[^\r\n]+/gi, "$1[redacted]");
  out = out.replace(/([?&](?:access_token|token|jwt|refresh_token)=)[^&\s]+/gi, "$1[redacted]");
  out = out.replace(
    /((?:api[_-]?key|x-api-key|client_secret|password|passwd|secret|sid|session)\s*[:=]\s*)("[^"]*"|'[^']*'|\S+)/gi,
    "$1[redacted]",
  );
  out = out.replace(
    /("(?:password|passwd|secret|token|access_token|refresh_token|refreshToken|cookie|sid|session)"\s*:\s*)"[^"]*"/gi,
    '$1"[redacted]"',
  );
  out = out.replace(/\b(sid|sessionid|jsessionid|phpsessid)=([^;\s]+)/gi, "$1=[redacted]");
  return out;
}

export function redactCookie(c: CookieRecord): CookieRecord {
  return { ...c, value: maskSecret(c.value) };
}

export function redactJwtToken(j: JwtToken): JwtToken {
  return { ...j, raw: redactJwt(j.raw), signature: j.signature ? "[sig]" : "" };
}

export function redactReplay(r: ReplayItem): ReplayItem {
  return { ...r, curl: redactText(r.curl), raw: redactText(r.raw), note: redactText(r.note) };
}

export function redactRequest(r: CapturedRequest): CapturedRequest {
  return {
    ...r,
    url: redactText(r.url),
    requestHeaders: r.requestHeaders.map((h) =>
      /authorization|cookie|api-?key|secret|token|password/i.test(h.name) ? { ...h, value: "[redacted]" } : { ...h, value: redactText(h.value) },
    ),
    responseHeaders: r.responseHeaders.map((h) =>
      /set-cookie|authorization|api-?key|secret|token/i.test(h.name) ? { ...h, value: "[redacted]" } : { ...h, value: redactText(h.value) },
    ),
    requestBody: r.requestBody ? redactText(r.requestBody) : r.requestBody,
    responseBody: r.responseBody ? redactText(r.responseBody) : r.responseBody,
  };
}

function redactFinding(f: Finding): Finding {
  return {
    ...f,
    title: redactText(f.title),
    why: redactText(f.why),
    how: redactText(f.how),
    evidence: f.evidence.map((e) => redactText(e)),
  };
}

export function redactWorkspace(ws: Workspace): Workspace {
  return {
    ...ws,
    aRaw: "",
    bRaw: "",
    requests: ws.requests.map(redactRequest),
    jwts: ws.jwts.map(redactJwtToken),
    cookies: ws.cookies.map(redactCookie),
    loot: ws.loot.map((l) =>
      l.kind === "secret" || l.kind === "key" ? { ...l, value: maskSecret(redactText(l.value)) } : { ...l, value: redactText(l.value) },
    ),
    replays: ws.replays.map(redactReplay),
    timeline: ws.timeline.map((t) => ({ ...t, detail: redactText(t.detail), label: redactText(t.label) })),
    findings: ws.findings.map(redactFinding),
    diffs: ws.diffs.map((d) => ({
      ...d,
      note: redactText(d.note),
      aSample: d.aSample ? redactRequest(d.aSample) : undefined,
      bSample: d.bSample ? redactRequest(d.bSample) : undefined,
    })),
    parseErrorA: ws.parseErrorA ? redactText(ws.parseErrorA) : ws.parseErrorA,
    parseErrorB: ws.parseErrorB ? redactText(ws.parseErrorB) : ws.parseErrorB,
  };
}
