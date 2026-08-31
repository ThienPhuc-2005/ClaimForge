import { createHash, randomBytes } from "node:crypto";

function b64url(buf: Buffer): string {
  return buf.toString("base64url");
}

export function randomOidcValue(bytes = 32): string {
  return b64url(randomBytes(bytes));
}

export function pkceVerifier(): string {
  return randomOidcValue(32);
}

/** RFC 7636 S256: BASE64URL(SHA256(ASCII(verifier))). */
export function pkceChallenge(verifier: string): string {
  return b64url(createHash("sha256").update(verifier, "ascii").digest());
}

export function hashOidcState(state: string): string {
  return createHash("sha256").update(state, "utf8").digest("hex");
}

export function newOidcLoginSecrets(): { state: string; nonce: string; verifier: string; challenge: string } {
  const state = randomOidcValue(32);
  const nonce = randomOidcValue(32);
  const verifier = pkceVerifier();
  return { state, nonce, verifier, challenge: pkceChallenge(verifier) };
}
