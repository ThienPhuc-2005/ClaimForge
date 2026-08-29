import { randomBytes } from "node:crypto";

/**
 * HMAC material for lab JWTs. Never imported from client modules.
 * Prefers LAB_HMAC_SECRET / BETTER_AUTH_SECRET so instances share a key;
 * otherwise a process-local random key (warm serverless reuse via globalThis).
 */
export function labHmacBytes(): Uint8Array {
  const g = globalThis as typeof globalThis & { __claimforgeLabHmac?: Uint8Array };
  if (g.__claimforgeLabHmac && g.__claimforgeLabHmac.length >= 16) return g.__claimforgeLabHmac;
  const env =
    (typeof process !== "undefined" && (process.env.LAB_HMAC_SECRET || process.env.BETTER_AUTH_SECRET)) || "";
  const raw = env.trim().length >= 16 ? env.trim() : randomBytes(32).toString("hex");
  g.__claimforgeLabHmac = new TextEncoder().encode(raw);
  return g.__claimforgeLabHmac;
}

/** Old client-bundled string — used only in tests to prove Fixed rejects leaked-secret forgeries. */
export const LEAKED_LAB_HMAC = "claimforge-lab-hs256";
