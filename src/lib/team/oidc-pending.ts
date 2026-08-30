import { requireSlug } from "./context.ts";
import type { TeamOidcConfig } from "./oidc-config.ts";
import { oidcSealKey } from "./oidc-config.ts";
import { hashOidcState } from "./oidc-pkce.ts";
import { sealUtf8, unsealUtf8 } from "./oidc-seal.ts";
import { TeamAuthError } from "./errors.ts";
import type { TeamSql } from "./types.ts";

export const OIDC_PENDING_TTL_MS = 10 * 60 * 1000;
/** Hard cap so spam GET /oidc/login cannot grow the table without bound. */
export const OIDC_PENDING_MAX_ROWS = 256;

async function sweepExpiredPending(sql: TeamSql, now: Date): Promise<void> {
  await sql.query(`DELETE FROM team_oidc_pending WHERE expires_at <= $1`, [now.toISOString()]);
}

async function evictOldestPending(sql: TeamSql, overflow: number): Promise<void> {
  if (overflow <= 0) return;
  await sql.query(
    `DELETE FROM team_oidc_pending
     WHERE state_hash IN (
       SELECT state_hash FROM team_oidc_pending
       ORDER BY created_at ASC, state_hash ASC
       LIMIT $1
     )`,
    [overflow],
  );
}

export async function insertOidcPending(
  sql: TeamSql,
  config: TeamOidcConfig,
  input: { state: string; nonce: string; verifier: string; challenge: string; slug: string; now?: Date },
): Promise<void> {
  const slug = requireSlug(input.slug);
  const now = input.now ?? new Date();
  const expires = new Date(now.getTime() + OIDC_PENDING_TTL_MS);
  await sql.transaction(async (tx) => {
    await sweepExpiredPending(tx, now);
    const counts = await tx.query<{ n: string }>("SELECT COUNT(*)::text AS n FROM team_oidc_pending");
    const n = Number(counts[0]?.n ?? "0");
    if (n >= OIDC_PENDING_MAX_ROWS) {
      await evictOldestPending(tx, n - OIDC_PENDING_MAX_ROWS + 1);
    }
    await tx.query(
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
  });
}

export async function consumeOidcPending(
  sql: TeamSql,
  config: TeamOidcConfig,
  state: string,
  now: Date = new Date(),
): Promise<{ nonce: string; verifier: string; slug: string; redirectUri: string }> {
  if (!state) throw new TeamAuthError("login failed");
  const row = await sql.transaction(async (tx) => {
    await sweepExpiredPending(tx, now);
    const rows = await tx.query<{
      nonce: string;
      verifier_ciphertext: string;
      redirect_uri: string;
      tenant_slug: string;
    }>(
      `DELETE FROM team_oidc_pending
       WHERE state_hash = $1 AND expires_at > $2
       RETURNING nonce, verifier_ciphertext, redirect_uri, tenant_slug`,
      [hashOidcState(state), now.toISOString()],
    );
    return rows[0] ?? null;
  });
  if (!row) throw new TeamAuthError("login failed");
  if (row.redirect_uri !== config.redirectUri) throw new TeamAuthError("login failed");
  return {
    nonce: row.nonce,
    verifier: unsealUtf8(row.verifier_ciphertext, oidcSealKey(config)),
    slug: row.tenant_slug,
    redirectUri: row.redirect_uri,
  };
}
