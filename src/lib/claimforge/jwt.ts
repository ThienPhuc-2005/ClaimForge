import type { JwtToken, ActorId } from "./types.ts";

function b64urlToUtf8(input: string): string {
  const pad = input.length % 4 === 0 ? "" : "=".repeat(4 - (input.length % 4));
  const b64 = input.replace(/-/g, "+").replace(/_/g, "/") + pad;
  try {
    const bin = atob(b64);
    const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
    return new TextDecoder().decode(bytes);
  } catch {
    return "";
  }
}

function parseJson(s: string): Record<string, unknown> {
  try {
    const v = JSON.parse(s) as unknown;
    return v && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : {};
  } catch {
    return {};
  }
}

const JWT_RE = /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/g;
const JWT_UNSIGNED_RE = /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.?/g;

export function extractJwtStrings(text: string): string[] {
  const found = new Set<string>();
  for (const m of text.matchAll(JWT_RE)) found.add(m[0]);
  for (const m of text.matchAll(JWT_UNSIGNED_RE)) {
    const t = m[0].replace(/\.$/, "");
    if (t.split(".").length >= 2) found.add(t);
  }
  return [...found];
}

export function inspectJwt(raw: string, actor: ActorId, source: string): JwtToken | null {
  const parts = raw.split(".").filter(Boolean);
  if (parts.length < 2) return null;
  const header = parseJson(b64urlToUtf8(parts[0] ?? ""));
  const payload = parseJson(b64urlToUtf8(parts[1] ?? ""));
  if (!Object.keys(header).length && !Object.keys(payload).length) return null;
  const alg = typeof header.alg === "string" ? header.alg : undefined;
  const issues: string[] = [];
  const algLc = (alg ?? "").toLowerCase();
  if (!alg || algLc === "none" || algLc === "n0ne") issues.push("alg is none / missing — signature not bound");
  if (parts.length < 3 || !(parts[2] ?? "").length) issues.push("unsigned (two-part) token");
  if (header.jwk) issues.push("embedded jwk in header (confused-deputy / key injection)");
  if (typeof header.jku === "string") issues.push(`jku remote key URL: ${header.jku}`);
  if (typeof header.x5u === "string") issues.push(`x5u remote cert URL: ${header.x5u}`);
  if (typeof header.kid === "string" && /(\.\.|\/|\\)/.test(header.kid))
    issues.push(`kid looks like a path: ${header.kid}`);
  const now = Date.now() / 1000;
  const exp = typeof payload.exp === "number" ? payload.exp : null;
  const nbf = typeof payload.nbf === "number" ? payload.nbf : null;
  const iat = typeof payload.iat === "number" ? payload.iat : null;
  if (exp == null) issues.push("no exp claim — token never expires");
  else {
    if (exp < now) issues.push("token already expired");
    if (exp - (iat ?? now) > 60 * 60 * 24 * 30) issues.push("lifetime > 30 days");
  }
  if (nbf != null && nbf > now + 60) issues.push("nbf in the future");
  const role = String(payload.role ?? payload.roles ?? payload.is_admin ?? payload.admin ?? "");
  if (/admin|root|superuser/i.test(role)) issues.push(`privileged role claim: ${role}`);
  if (payload.sub && payload.userId && String(payload.sub) !== String(payload.userId))
    issues.push("sub and userId disagree");
  return { actor, raw, source, header, payload, alg, parts: parts.length, issues };
}

export function utf8ToB64url(s: string): string {
  const bytes = new TextEncoder().encode(s);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function mintJwt(
  header: Record<string, unknown>,
  payload: Record<string, unknown>,
  signature = "",
): string {
  const h = utf8ToB64url(JSON.stringify(header));
  const p = utf8ToB64url(JSON.stringify(payload));
  return signature ? `${h}.${p}.${signature}` : `${h}.${p}.`;
}

export function jwtSubject(token: JwtToken): string | null {
  const v = token.payload.sub ?? token.payload.user_id ?? token.payload.uid ?? token.payload.userId;
  return v == null ? null : String(v);
}
