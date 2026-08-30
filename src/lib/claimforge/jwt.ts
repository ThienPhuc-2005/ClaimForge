import {
  SignJWT,
  jwtVerify,
  decodeJwt,
  decodeProtectedHeader,
  importSPKI,
  importX509,
  createLocalJWKSet,
  type JWTVerifyGetKey,
} from "jose";
import type { JwtToken, ActorId, JwtSigStatus } from "./types.ts";
import { fetchJwksDocument, type JwksUrlPolicy } from "./jwks-fetch.ts";

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

const ASYM_ALGS = ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512"] as const;
const HS_ALGS = ["HS256", "HS384", "HS512"] as const;

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

function secretKey(secret: string): Uint8Array {
  return new TextEncoder().encode(secret);
}

export function inspectJwt(raw: string, actor: ActorId, source: string): JwtToken | null {
  const segs = raw.replace(/\.$/, "").split(".");
  if (segs.length < 2) return null;
  const signature = segs.length >= 3 ? (segs[2] ?? "") : "";
  let header: Record<string, unknown> = parseJson(b64urlToUtf8(segs[0] ?? ""));
  let payload: Record<string, unknown> = parseJson(b64urlToUtf8(segs[1] ?? ""));
  try {
    header = { ...decodeProtectedHeader(raw), ...header };
  } catch {
    /* compact parse already filled header */
  }
  try {
    payload = { ...decodeJwt(raw), ...payload };
  } catch {
    /* unsigned / malformed still parsed via b64 */
  }
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
  if (payload.iss == null || payload.iss === "") issues.push("no iss claim — issuer not bound");
  if (payload.aud == null || payload.aud === "") issues.push("no aud claim — audience not bound");
  const role = String(payload.role ?? payload.roles ?? payload.is_admin ?? payload.admin ?? "");
  if (/admin|root|superuser/i.test(role)) issues.push(`privileged role claim: ${role}`);
  if (payload.sub && payload.userId && String(payload.sub) !== String(payload.userId))
    issues.push("sub and userId disagree");
  const parts = signature.length ? 3 : 2;
  return { actor, raw, source, header, payload, alg, parts, signature, sigStatus, issues };
}

export interface JwtVerifyOptions {
  secret?: string;
  publicKeyPem?: string;
  jwksUrl?: string;
  jwksConfirmed?: boolean;
  jwksFetch?: typeof fetch;
  jwksPolicy?: JwksUrlPolicy;
  issuer?: string;
  audience?: string | string[];
}

async function importPublic(pem: string, alg: string): Promise<CryptoKey> {
  const trimmed = pem.trim();
  if (/BEGIN CERTIFICATE/.test(trimmed)) return importX509(trimmed, alg);
  return importSPKI(trimmed, alg);
}

function verifyOpts(opts: JwtVerifyOptions) {
  return {
    issuer: opts.issuer || undefined,
    audience: opts.audience || undefined,
  };
}

/** Verify HS256 (or reject alg=none) with jose. Mutates a copy of inspectJwt. */
export async function verifyJwtWithSecret(token: JwtToken, secret: string): Promise<JwtToken> {
  return verifyJwtWithKey(token, { secret });
}

/** Verify HS* with a secret, RS/PS/ES with PEM or JWKS, optionally checking iss/aud. */
export async function verifyJwtWithKey(token: JwtToken, opts: JwtVerifyOptions): Promise<JwtToken> {
  const next = { ...token, issues: [...token.issues] };
  const algLc = (token.alg ?? "").toLowerCase();
  if (!token.signature || algLc === "none" || algLc === "n0ne") {
    next.sigStatus = "unsigned";
    return next;
  }
  const extra = verifyOpts(opts);
  try {
    let key: CryptoKey | Uint8Array | JWTVerifyGetKey;
    let algorithms: string[];
    if (opts.jwksUrl) {
      const { jwks } = await fetchJwksDocument(opts.jwksUrl, {
        confirmed: Boolean(opts.jwksConfirmed),
        fetchImpl: opts.jwksFetch,
        policy: opts.jwksPolicy,
      });
      key = createLocalJWKSet(jwks as Parameters<typeof createLocalJWKSet>[0]);
      algorithms = [...ASYM_ALGS];
    } else if (opts.publicKeyPem) {
      const alg = token.alg && ASYM_ALGS.includes(token.alg as (typeof ASYM_ALGS)[number]) ? token.alg : "RS256";
      key = await importPublic(opts.publicKeyPem, alg);
      algorithms = [...ASYM_ALGS];
    } else if (opts.secret) {
      key = secretKey(opts.secret);
      algorithms = [...HS_ALGS];
    } else {
      next.issues.push("no HMAC secret, public key, or JWKS URL provided");
      return next;
    }
    const { payload, protectedHeader } = await jwtVerify(token.raw, key, {
      algorithms,
      ...extra,
    });
    next.sigStatus = "verified";
    next.header = { ...next.header, ...(protectedHeader as Record<string, unknown>) };
    next.payload = { ...next.payload, ...(payload as Record<string, unknown>) };
    next.issues = next.issues.filter((i) => !/unsigned/i.test(i));
    if (opts.issuer) next.issues = next.issues.filter((i) => !/no iss claim/i.test(i));
    if (opts.audience) next.issues = next.issues.filter((i) => !/no aud claim/i.test(i));
  } catch (e) {
    next.sigStatus = "invalid";
    next.issues.push(`signature invalid (${e instanceof Error ? e.message : "verify failed"})`);
  }
  return next;
}

export function utf8ToB64url(s: string): string {
  const bytes = new TextEncoder().encode(s);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Local compact mint. Empty signature → trailing dot (alg=none). Dummy third arg is a raw signature, not HMAC. */
export function mintJwt(
  header: Record<string, unknown>,
  payload: Record<string, unknown>,
  signature = "",
): string {
  const alg = String(header.alg ?? "none").toLowerCase();
  if (!signature && (alg === "none" || alg === "n0ne" || !alg)) {
    const h = utf8ToB64url(JSON.stringify({ alg: "none", typ: "JWT", ...omitAlg(header) }));
    const p = utf8ToB64url(JSON.stringify(payload));
    return `${h}.${p}.`;
  }
  const h = utf8ToB64url(JSON.stringify(header));
  const p = utf8ToB64url(JSON.stringify(payload));
  return signature ? `${h}.${p}.${signature}` : `${h}.${p}.`;
}

function omitAlg(header: Record<string, unknown>): Record<string, unknown> {
  const { alg: _a, ...rest } = header;
  return rest;
}

/** Real HMAC-SHA256 via jose. */
export async function signHs256(
  payload: Record<string, unknown>,
  secret: string,
  header: Record<string, unknown> = {},
): Promise<string> {
  const { alg: _a, ...rest } = header;
  let jwt = new SignJWT(payload).setProtectedHeader({ alg: "HS256", typ: "JWT", ...rest });
  if (typeof payload.iat !== "number") jwt = jwt.setIssuedAt();
  if (typeof payload.exp !== "number") jwt = jwt.setExpirationTime("2h");
  if (typeof payload.iss === "string") jwt = jwt.setIssuer(payload.iss);
  if (typeof payload.aud === "string") jwt = jwt.setAudience(payload.aud);
  return jwt.sign(secretKey(secret));
}

export async function signRs256(
  payload: Record<string, unknown>,
  privateKey: CryptoKey,
  header: Record<string, unknown> = {},
): Promise<string> {
  const { alg: _a, ...rest } = header;
  let jwt = new SignJWT(payload).setProtectedHeader({ alg: "RS256", typ: "JWT", ...rest });
  if (typeof payload.iat !== "number") jwt = jwt.setIssuedAt();
  if (typeof payload.exp !== "number") jwt = jwt.setExpirationTime("2h");
  if (typeof payload.iss === "string") jwt = jwt.setIssuer(payload.iss);
  if (typeof payload.aud === "string") jwt = jwt.setAudience(payload.aud);
  return jwt.sign(privateKey);
}

export function jwtSubject(token: JwtToken): string | null {
  const v = token.payload.sub ?? token.payload.user_id ?? token.payload.uid ?? token.payload.userId;
  return v == null ? null : String(v);
}
