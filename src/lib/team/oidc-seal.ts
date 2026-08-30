import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";
import { TeamAuthError } from "./errors.ts";

const PREFIX = "v1.";
const IV_LEN = 12;
const TAG_LEN = 16;

export function deriveSealKey(secret: string): Buffer {
  if (!secret || secret.length < 32) throw new TeamAuthError("oidc is not configured");
  return createHash("sha256").update(secret, "utf8").digest();
}

export function sealUtf8(plaintext: string, key: Buffer): string {
  if (key.length !== 32) throw new TeamAuthError("oidc is not configured");
  const iv = randomBytes(IV_LEN);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const ct = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return PREFIX + Buffer.concat([iv, ct, tag]).toString("base64url");
}

export function unsealUtf8(blob: string, key: Buffer): string {
  if (key.length !== 32) throw new TeamAuthError("oidc is not configured");
  if (!blob.startsWith(PREFIX)) throw new TeamAuthError("pending state is invalid");
  let buf: Buffer;
  try {
    buf = Buffer.from(blob.slice(PREFIX.length), "base64url");
  } catch {
    throw new TeamAuthError("pending state is invalid");
  }
  if (buf.length < IV_LEN + TAG_LEN + 1) throw new TeamAuthError("pending state is invalid");
  const iv = buf.subarray(0, IV_LEN);
  const tag = buf.subarray(buf.length - TAG_LEN);
  const ct = buf.subarray(IV_LEN, buf.length - TAG_LEN);
  try {
    const decipher = createDecipheriv("aes-256-gcm", key, iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ct), decipher.final()]).toString("utf8");
  } catch {
    throw new TeamAuthError("pending state is invalid");
  }
}
