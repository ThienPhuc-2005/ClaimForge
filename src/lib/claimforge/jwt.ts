import type { JwtToken, ActorId, JwtSigStatus } from "./types.ts";

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

/** Compact JWT: two or three segments. Third group is greedy so a signature is not split off as a second token. */
const JWT_RE = /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]*)?/g;

export function extractJwtStrings(text: string): string[] {
  const found = new Set<string>();
  for (const m of text.matchAll(JWT_RE)) {
    const raw = m[0];
    const segs = raw.replace(/\.$/, "").split(".");
    if (segs.length >= 3 && (segs[2] ?? "").length) {
      found.add(`${segs[0]}.${segs[1]}.${segs[2]}`);
    } else if (segs.length >= 2) {
      found.add(`${segs[0]}.${segs[1]}`);
    }
  }
  return [...found];
}

export function inspectJwt(raw: string, actor: ActorId, source: string): JwtToken | null {
  const segs = raw.replace(/\.$/, "").split(".");
  if (segs.length < 2) return null;
  const signature = segs.length >= 3 ? (segs[2] ?? "") : "";
  const header = parseJson(b64urlToUtf8(segs[0] ?? ""));
  const payload = parseJson(b64urlToUtf8(segs[1] ?? ""));
  if (!Object.keys(header).length && !Object.keys(payload).length) return null;
  const alg = typeof header.alg === "string" ? header.alg : undefined;
  const issues: string[] = [];
  const algLc = (alg ?? "").toLowerCase();
  const sigStatus: JwtSigStatus = signature.length ? "unverified" : "unsigned";
  if (!alg || algLc === "none" || algLc === "n0ne") issues.push("alg is none / missing — signature not bound");
  if (sigStatus === "unsigned") issues.push("unsigned (two-part) token");
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
  const parts = signature.length ? 3 : 2;
  return { actor, raw, source, header, payload, alg, parts, signature, sigStatus, issues };
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
