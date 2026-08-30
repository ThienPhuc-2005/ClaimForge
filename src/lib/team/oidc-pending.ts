import { requireSlug } from "./context.ts";
import type { TeamOidcConfig } from "./oidc-config.ts";
import { oidcSealKey } from "./oidc-config.ts";
import { hashOidcState } from "./oidc-pkce.ts";
import { sealUtf8, unsealUtf8 } from "./oidc-seal.ts";
import { TeamAuthError } from "./errors.ts";
import type { TeamSql } from "./types.ts";

export const OIDC_PENDING_TTL_MS = 10 * 60 * 1000;

export async function insertOidcPending(
  sql: TeamSql,
  config: TeamOidcConfig,
  input: { state: string; nonce: string; verifier: string; challenge: string; slug: string; now?: Date },
): Promise<void> {
  const slug = requireSlug(input.slug);
  const now = input.now ?? new Date();
  const expires = new Date(now.getTime() + OIDC_PENDING_TTL_MS);
  await sql.query(
    `INSERT INTO team_oidc_pending (
      state_hash, nonce, code_challenge, verifier_ciphertext, redirect_uri, tenant_slug, expires_at, created_at
    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
    [
      hashOidcState(input.state),
      input.nonce,
      input.challenge,
      sealUtf8(input.verifier, oidcSealKey(config)),
      config.redirectUri,
      slug,
      expires.toISOString(),
      now.toISOString(),
    ],
  );
}

export async function consumeOidcPending(
  sql: TeamSql,
  config: TeamOidcConfig,
  state: string,
  now: Date = new Date(),
): Promise<{ nonce: string; verifier: string; slug: string; redirectUri: string }> {
  if (!state) throw new TeamAuthError("login failed");
  const rows = await sql.query<{
    nonce: string;
    verifier_ciphertext: string;
    redirect_uri: string;
    tenant_slug: string;
  }>(
    `UPDATE team_oidc_pending
     SET consumed_at = $2
     WHERE state_hash = $1
       AND consumed_at IS NULL
       AND expires_at > $2
     RETURNING nonce, verifier_ciphertext, redirect_uri, tenant_slug`,
    [hashOidcState(state), now.toISOString()],
  );
  const row = rows[0];
  if (!row) throw new TeamAuthError("login failed");
  if (row.redirect_uri !== config.redirectUri) throw new TeamAuthError("login failed");
  return {
    nonce: row.nonce,
    verifier: unsealUtf8(row.verifier_ciphertext, oidcSealKey(config)),
    slug: row.tenant_slug,
    redirectUri: row.redirect_uri,
  };
}
