import type { CapturedRequest, CookieRecord, Finding, JwtToken, ReplayItem, Workspace } from "./types.ts";
import { extractJwtStrings } from "./jwt.ts";

const SECRET_KEY =
  /^(passwords?|passwd|pwd|secrets?|tokens?|access[_-]?token|refresh[_-]?token|id[_-]?token|authorization|auth|cookie|set-cookie|client[_-]?secret|api[_-]?key|x-api-key|private[_-]?key|secret[_-]?key|sid|session|sessionid|jsessionid|phpsessid)$/i;

const SECRET_KEY_SUFFIX = /(secret|token|password|passwd|apikey|api_key|private_key)$/i;

export function maskSecret(value: string): string {
  if (!value) return value;
  return "[redacted]";
}

export function redactJwt(raw: string): string {
  const segs = raw.split(".");
  if (segs.length < 2) return "[redacted]";
  return `${segs[0]}.[payload].[sig]`;
}

function isSecretKey(key: string): boolean {
  const compact = key.replace(/[-_\s]/g, "");
  return SECRET_KEY.test(key) || SECRET_KEY.test(compact) || SECRET_KEY_SUFFIX.test(key);
}

export function redactJsonValue(value: unknown, parentKey?: string): unknown {
  if (parentKey && isSecretKey(parentKey)) return "[redacted]";
  if (Array.isArray(value)) return value.map((v) => redactJsonValue(v, parentKey));
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      out[k] = isSecretKey(k) ? "[redacted]" : redactJsonValue(v, k);
    }
    return out;
  }
  if (typeof value === "string") return redactPlain(value);
  return value;
}

function redactPlain(input: string): string {
  let out = input;
  for (const t of extractJwtStrings(out)) out = out.split(t).join(redactJwt(t));
  out = out.replace(/Bearer\s+\S+/gi, "Bearer [redacted]");
  out = out.replace(/Basic\s+\S+/gi, "Basic [redacted]");
  out = out.replace(/((?:Set-)?Cookie:\s*)[^\r\n]+/gi, "$1[redacted]");
  out = out.replace(/([?&](?:access_token|refresh_token|id_token|token|jwt|fragment)=)[^&\s#]+/gi, "$1[redacted]");
  out = out.replace(/(#[^?\s]*token[^?\s]*)/gi, "#[redacted]");
  out = out.replace(
    /((?:api[_-]?key|x-api-key|client_secret|clientSecret|password|passwd|secret|private_key|privateKey|sid|session)\s*[:=]\s*)("[^"]*"|'[^']*'|\S+)/gi,
    "$1[redacted]",
  );
  out = out.replace(
    /("(?:password|passwd|secret|token|access_token|refresh_token|refreshToken|id_token|authorization|cookie|clientSecret|client_secret|apiKey|api_key|private_key|privateKey|sid|session)"\s*:\s*)"(?:\\.|[^"\\])*"/gi,
    '$1"[redacted]"',
  );
  out = out.replace(/\b(sid|sessionid|jsessionid|phpsessid)=([^;\s]+)/gi, "$1=[redacted]");
  out = out.replace(/-----BEGIN [^-]+-----[\s\S]*?-----END [^-]+-----/g, "[redacted]");
  return out;
}

export function redactText(input: string): string {
  const t = input.trim();
  if ((t.startsWith("{") && t.endsWith("}")) || (t.startsWith("[") && t.endsWith("]"))) {
    try {
      const parsed = JSON.parse(input) as unknown;
      return JSON.stringify(redactJsonValue(parsed));
    } catch {
      /* fall through to regex */
    }
  }
  return redactPlain(input);
}

export function redactCookie(c: CookieRecord): CookieRecord {
  return { ...c, value: maskSecret(c.value) };
}

export function redactJwtToken(j: JwtToken): JwtToken {
  return {
    ...j,
    raw: redactJwt(j.raw),
    signature: j.signature ? "[sig]" : "",
    payload: redactJsonValue(j.payload) as Record<string, unknown>,
    issues: j.issues.map((i) => redactText(i)),
  };
}

export function redactReplay(r: ReplayItem): ReplayItem {
  return {
    ...r,
    curl: redactText(r.curl),
    raw: redactText(r.raw),
    note: redactText(r.note),
    headerDiff: r.headerDiff?.map((d) => ({
      name: d.name,
      before: redactText(d.before),
      after: redactText(d.after),
    })),
  };
}

export function redactRequest(r: CapturedRequest): CapturedRequest {
  return {
    ...r,
    url: redactText(r.url),
    path: redactText(r.path),
    requestHeaders: r.requestHeaders.map((h) =>
      /authorization|cookie|api-?key|secret|token|password|private|csrf|x-api-key/i.test(h.name)
        ? { ...h, value: "[redacted]" }
        : { ...h, value: redactText(h.value) },
    ),
    responseHeaders: r.responseHeaders.map((h) =>
      /set-cookie|authorization|api-?key|secret|token|password|private/i.test(h.name)
        ? { ...h, value: "[redacted]" }
        : { ...h, value: redactText(h.value) },
    ),
    requestBody: r.requestBody ? redactText(r.requestBody) : r.requestBody,
    responseBody: r.responseBody ? redactText(r.responseBody) : r.responseBody,
    query: Object.fromEntries(
      Object.entries(r.query).map(([k, v]) =>
        /token|jwt|secret|password|key|sid|session/i.test(k) ? [k, "[redacted]"] : [k, redactText(v)],
      ),
    ),
  };
}

function redactFinding(f: Finding): Finding {
  return {
    ...f,
    title: redactText(f.title),
    why: redactText(f.why),
    how: redactText(f.how),
    evidence: f.evidence.map((e) => redactText(e)),
    canonical: f.canonical
      ? {
          ...f.canonical,
          endpoint: redactText(f.canonical.endpoint),
          ownershipReason: redactText(f.canonical.ownershipReason),
        }
      : f.canonical,
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
      l.kind === "secret" || l.kind === "key" ? { ...l, value: maskSecret(l.value) } : { ...l, value: redactText(l.value) },
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
    graph: {
      nodes: ws.graph.nodes.map((n) => ({ ...n, label: redactText(n.label) })),
      edges: ws.graph.edges.map((e) => ({ ...e, via: redactText(e.via) })),
    },
    wordlists: {
      ids: ws.wordlists.ids.map((x) => redactText(x)),
      emails: ws.wordlists.emails.map((x) => redactText(x)),
      roles: ws.wordlists.roles.map((x) => redactText(x)),
      hosts: ws.wordlists.hosts.map((x) => redactText(x)),
    },
    paths: ws.paths.map((p) => ({
      ...p,
      title: redactText(p.title),
      objective: redactText(p.objective),
      steps: p.steps.map((s) => redactText(s)),
    })),
    idsA: ws.idsA.map((x) => redactText(x)),
    idsB: ws.idsB.map((x) => redactText(x)),
    parseErrorA: ws.parseErrorA ? redactText(ws.parseErrorA) : ws.parseErrorA,
    parseErrorB: ws.parseErrorB ? redactText(ws.parseErrorB) : ws.parseErrorB,
  };
}
