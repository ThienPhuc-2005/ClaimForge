import { createHash } from "node:crypto";
import { TeamValidationError } from "./errors.ts";

/**
 * Stable membership key: `oidc:` + sha256(JSON.stringify([iss, sub])).
 * `sub` is the exact OIDC subject — no trim or other normalization.
 */
export function oidcUserKey(iss: unknown, sub: unknown): string {
  if (typeof iss !== "string" || typeof sub !== "string") {
    throw new TeamValidationError("oidc subject is invalid");
  }
  const issuer = iss.trim();
  const subject = sub;
  if (!issuer || issuer.length > 512 || issuer.includes("\0")) {
    throw new TeamValidationError("oidc subject is invalid");
  }
  if (subject.length === 0 || subject.length > 256 || subject.includes("\0")) {
    throw new TeamValidationError("oidc subject is invalid");
  }
  const digest = createHash("sha256").update(JSON.stringify([issuer, subject]), "utf8").digest("hex");
  return `oidc:${digest}`;
}
