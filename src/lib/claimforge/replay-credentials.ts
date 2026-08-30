import type { CapturedRequest, HttpHeader } from "./types.ts";

export interface ReplayCredentialPolicy {
  extraHeaderNames: string[];
  replaceSecretQueryAndBody: boolean;
}

export const DEFAULT_REPLAY_CREDENTIAL_POLICY: ReplayCredentialPolicy = {
  extraHeaderNames: [],
  replaceSecretQueryAndBody: true,
};

export interface ActorCredentialSet {
  actor: string;
  headers: HttpHeader[];
  bearer?: string;
  cookie?: string;
  kinds: string[];
}

export interface CredentialDiffRow {
  name: string;
  before: string;
  after: string;
}

export interface CredentialBoundaryResult {
  request: CapturedRequest;
  strippedNames: string[];
  attachedKinds: string[];
  sourceActor: string;
  headerDiff: CredentialDiffRow[];
}

const KNOWN_CREDENTIAL_HEADERS = new Set([
  "authorization",
  "proxy-authorization",
  "cookie",
  "set-cookie",
  "x-api-key",
  "api-key",
  "apikey",
  "x-apikey",
  "x-api-token",
  "api-token",
  "x-auth-token",
  "x-access-token",
  "x-session-token",
  "session-token",
  "x-token",
  "authentication",
  "x-authorization",
  "x-csrf-token",
  "x-xsrf-token",
  "csrf-token",
  "xsrf-token",
  "x-csrf",
  "anti-csrf-token",
  "x-anti-csrf",
  "requestverificationtoken",
  "x-requestverificationtoken",
  "x-amz-security-token",
]);

const TOKENISH_HEADER = /(?:^|[-_])(auth|token|secret|credential|api[-_]?key|bearer|csrf|xsrf|session)(?:$|[-_])/i;

const SECRET_FIELD = /^(password|passwd|secret|api[_-]?key|client_secret|access_token|refresh_token|id_token|auth_token|private_key|csrf|xsrf|csrf[_-]?token|xsrf[_-]?token|_csrf|token|session|jwt|code)$/i;

function norm(name: string): string {
  return name.trim().toLowerCase();
}

export function isCredentialHeader(name: string, extra: string[] = []): boolean {
  const n = norm(name);
  if (!n) return false;
  if (KNOWN_CREDENTIAL_HEADERS.has(n)) return true;
  if (extra.some((e) => norm(e) === n)) return true;
  if (TOKENISH_HEADER.test(n) && n !== "content-type" && n !== "accept") return true;
  return false;
}

export function isSecretFieldName(name: string): boolean {
  return SECRET_FIELD.test(name);
}

export function maskCredential(value: string): string {
  const v = value.trim();
  if (!v) return "";
  if (/^bearer\s+/i.test(v)) {
    const rest = v.replace(/^bearer\s+/i, "");
    return `Bearer ${maskCredential(rest)}`;
  }
  if (v.length <= 10) return `•••• (${v.length})`;
  return `${v.slice(0, 2)}…${v.slice(-2)} (${v.length})`;
}

function canonicalHeaderName(name: string): string {
  const n = norm(name);
  if (n === "authorization") return "Authorization";
  if (n === "proxy-authorization") return "Proxy-Authorization";
  if (n === "cookie") return "Cookie";
  if (n === "set-cookie") return "Set-Cookie";
  if (n === "x-api-key") return "X-API-Key";
  if (n === "api-key") return "API-Key";
  if (n === "x-csrf-token") return "X-CSRF-Token";
  if (n === "x-xsrf-token") return "X-XSRF-Token";
  return name;
}

export function stripSourceCredentials(
  sample: CapturedRequest,
  policy: ReplayCredentialPolicy = DEFAULT_REPLAY_CREDENTIAL_POLICY,
): { request: CapturedRequest; strippedNames: string[] } {
  const extra = policy.extraHeaderNames;
  const strippedNames: string[] = [];
  const requestHeaders = sample.requestHeaders.filter((h) => {
    if (isCredentialHeader(h.name, extra)) {
      strippedNames.push(h.name);
      return false;
    }
    return true;
  });

  const query = { ...sample.query };
  for (const k of Object.keys(query)) {
    if (isSecretFieldName(k) || isCredentialHeader(k, extra)) {
      delete query[k];
      strippedNames.push(`query.${k}`);
    }
  }

  let url = sample.url;
  try {
    const u = new URL(sample.url);
    for (const k of [...u.searchParams.keys()]) {
      if (isSecretFieldName(k) || isCredentialHeader(k, extra)) {
        u.searchParams.delete(k);
        if (!strippedNames.includes(`query.${k}`)) strippedNames.push(`query.${k}`);
      }
    }
    url = u.toString();
  } catch {
    /* leave url */
  }

  let requestBody = sample.requestBody;
  if (policy.replaceSecretQueryAndBody && requestBody) {
    try {
      const parsed = JSON.parse(requestBody) as unknown;
      if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
        const obj = { ...(parsed as Record<string, unknown>) };
        let hit = false;
        for (const k of Object.keys(obj)) {
          if (isSecretFieldName(k)) {
            delete obj[k];
            strippedNames.push(`body.${k}`);
            hit = true;
          }
        }
        if (hit) requestBody = JSON.stringify(obj);
      }
    } catch {
      /* not json */
    }
  }

  return {
    request: { ...sample, url, query, requestHeaders, requestBody },
    strippedNames: [...new Set(strippedNames)],
  };
}

export function extractActorCredentials(
  reqs: CapturedRequest[],
  extra: string[] = [],
): ActorCredentialSet | undefined {
  const live = reqs.filter((r) => r.method !== "PASTE");
  if (!live.length) return undefined;
  const actor = live[0]!.actor;
  const map = new Map<string, HttpHeader>();
  for (const r of live) {
    for (const h of r.requestHeaders) {
      if (!h.value.trim()) continue;
      if (isCredentialHeader(h.name, extra)) {
        map.set(norm(h.name), { name: canonicalHeaderName(h.name), value: h.value });
      }
    }
  }
  if (!map.size) return undefined;
  const headers = [...map.values()];
  const kinds = headers.map((h) => h.name);
  const auth = map.get("authorization")?.value;
  const m = auth?.match(/^Bearer\s+(\S+)/i);
  return {
    actor,
    headers,
    bearer: m?.[1],
    cookie: map.get("cookie")?.value,
    kinds,
  };
}

export function credentialSetFromBearer(actor: string, bearer: string): ActorCredentialSet {
  return {
    actor,
    bearer,
    headers: [{ name: "Authorization", value: `Bearer ${bearer}` }],
    kinds: ["Authorization"],
  };
}

export function attachActorCredentials(
  cleaned: CapturedRequest,
  creds: ActorCredentialSet,
): CapturedRequest {
  const headers = [...cleaned.requestHeaders];
  for (const h of creds.headers) {
    const i = headers.findIndex((x) => norm(x.name) === norm(h.name));
    if (i >= 0) headers[i] = { name: canonicalHeaderName(h.name), value: h.value };
    else headers.push({ name: canonicalHeaderName(h.name), value: h.value });
  }
  return { ...cleaned, requestHeaders: headers };
}

function headerMap(list: HttpHeader[]): Map<string, string> {
  const m = new Map<string, string>();
  for (const h of list) m.set(norm(h.name), h.value);
  return m;
}

export function applyCredentialBoundary(
  sample: CapturedRequest,
  creds: ActorCredentialSet,
  policy: ReplayCredentialPolicy = DEFAULT_REPLAY_CREDENTIAL_POLICY,
): CredentialBoundaryResult {
  const { request: cleaned, strippedNames } = stripSourceCredentials(sample, policy);
  const request = attachActorCredentials(cleaned, creds);
  const before = headerMap(sample.requestHeaders);
  const after = headerMap(request.requestHeaders);
  const names = new Set([...before.keys(), ...after.keys()]);
  const headerDiff: CredentialDiffRow[] = [];
  for (const n of names) {
    const b = before.get(n);
    const a = after.get(n);
    if (b === a) continue;
    if (!isCredentialHeader(n, policy.extraHeaderNames) && b !== undefined && a !== undefined) continue;
    if (b === a) continue;
    if (b == null && a == null) continue;
    if ((b ?? "") === (a ?? "")) continue;
    headerDiff.push({
      name: canonicalHeaderName(n),
      before: b == null ? "(absent)" : maskCredential(b),
      after: a == null ? "(stripped)" : maskCredential(a),
    });
  }
  return {
    request,
    strippedNames,
    attachedKinds: creds.kinds,
    sourceActor: creds.actor,
    headerDiff,
  };
}

export function replayHasForeignSecret(blob: string, foreignValues: string[]): boolean {
  return foreignValues.some((v) => v.length > 3 && blob.includes(v));
}
