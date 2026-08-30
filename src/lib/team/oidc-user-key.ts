import { createHash } from "node:crypto";
import { TeamValidationError } from "./errors.ts";

/** Stable membership key: `oidc:` + sha256(JSON.stringify([iss, sub])). */
export function oidcUserKey(iss: unknown, sub: unknown): string {
  if (typeof iss !== "string" || typeof sub !== "string") {
    throw new TeamValidationError("oidc subject is invalid");
  }
  const issuer = iss.trim();
  const subject = sub.trim();
  if (!issuer || !subject || issuer.length > 512 || subject.length > 256 || issuer.includes("\0") || subject.includes("\0")) {
    throw new TeamValidationError("oidc subject is invalid");
  }
  const digest = createHash("sha256").update(JSON.stringify([issuer, subject]), "utf8").digest("hex");
  return `oidc:${digest}`;
}
