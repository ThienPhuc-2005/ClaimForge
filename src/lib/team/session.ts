import { createHash, randomBytes, randomUUID } from "node:crypto";
import { requireActiveMember, resolveTenantContext, type TenantContext } from "./context.ts";
import { TeamAuthError, TeamNotFoundError } from "./errors.ts";
import type { TeamSql } from "./types.ts";

export const SESSION_TTL_MS = 12 * 60 * 60 * 1000;
export const SESSION_ROTATE_AFTER_MS = 6 * 60 * 60 * 1000;
/** Previous token stays valid this long after an atomic rotate (concurrent in-flight requests). */
export const SESSION_ROTATE_GRACE_MS = 60 * 1000;

export type TeamSession = {
  id: string;
  tenantId: string;
  userKey: string;
  createdAt: Date;
  rotatedAt: Date | null;
  expiresAt: Date;
};

type SessionRow = {
  id: string;
  token_hash: string;
  tenant_id: string;
  user_key: string;
  created_at: string | Date;
  rotated_at: string | Date | null;
  expires_at: string | Date;
};

function stamp(value: string | Date): Date {
  return value instanceof Date ? value : new Date(value);
}

function hashToken(token: string): string {
  return createHash("sha256").update(token, "utf8").digest("hex");
}

function newToken(): string {
  return randomBytes(32).toString("base64url");
}

function mapSession(row: SessionRow): TeamSession {
  return {
    id: row.id,
    tenantId: row.tenant_id,
    userKey: row.user_key,
    createdAt: stamp(row.created_at),
    rotatedAt: row.rotated_at ? stamp(row.rotated_at) : null,
    expiresAt: stamp(row.expires_at),
  };
}

export async function mintTeamSession(
  sql: TeamSql,
  ctx: TenantContext,
  now: Date = new Date(),
): Promise<{ token: string; session: TeamSession }> {
  const ident = await requireActiveMember(sql, ctx);
  const token = newToken();
  const id = randomUUID();
  const expiresAt = new Date(now.getTime() + SESSION_TTL_MS);
  const rows = await sql.query<SessionRow>(
    `INSERT INTO team_session (id, token_hash, tenant_id, user_key, expires_at, created_at)
     VALUES ($1, $2, $3, $4, $5, $6)
     RETURNING id, token_hash, tenant_id, user_key, created_at, rotated_at, expires_at`,
    [id, hashToken(token), ident.tenantId, ident.userKey, expiresAt.toISOString(), now.toISOString()],
  );
  if (!rows[0]) throw new TeamAuthError("login failed");
  return { token, session: mapSession(rows[0]) };
}

export async function loadTeamSession(
  sql: TeamSql,
  token: string,
  now: Date = new Date(),
): Promise<{ session: TeamSession; context: TenantContext } | null> {
  if (!token) return null;
  const graceStart = new Date(now.getTime() - SESSION_ROTATE_GRACE_MS);
  const rows = await sql.query<SessionRow>(
    `SELECT id, token_hash, tenant_id, user_key, created_at, rotated_at, expires_at
     FROM team_session
     WHERE revoked_at IS NULL AND expires_at > $2
       AND (
         token_hash = $1
         OR (prev_token_hash = $1 AND rotated_at IS NOT NULL AND rotated_at > $3)
       )`,
    [hashToken(token), now.toISOString(), graceStart.toISOString()],
  );
  const row = rows[0];
  if (!row) return null;
  try {
    const context = await resolveTenantContext(sql, row.user_key, row.tenant_id);
    await requireActiveMember(sql, context);
    return { session: mapSession(row), context };
  } catch (err) {
    if (err instanceof TeamNotFoundError) return null;
    throw err;
  }
}

export function sessionNeedsRotation(session: TeamSession, now: Date = new Date()): boolean {
  const pivot = session.rotatedAt ?? session.createdAt;
  return now.getTime() - pivot.getTime() >= SESSION_ROTATE_AFTER_MS;
}

export async function rotateTeamSession(
  sql: TeamSql,
  token: string,
  now: Date = new Date(),
): Promise<{ token: string; session: TeamSession; context: TenantContext } | null> {
  const loaded = await loadTeamSession(sql, token, now);
  if (!loaded) return null;
  if (!sessionNeedsRotation(loaded.session, now)) return { token, ...loaded };
  const next = newToken();
  const oldHash = hashToken(token);
  return sql.transaction(async (tx) => {
    const rows = await tx.query<SessionRow>(
      `UPDATE team_session
       SET token_hash = $1, prev_token_hash = $4, rotated_at = $2
       WHERE id = $3 AND token_hash = $4 AND revoked_at IS NULL AND expires_at > $2
       RETURNING id, token_hash, tenant_id, user_key, created_at, rotated_at, expires_at`,
      [hashToken(next), now.toISOString(), loaded.session.id, oldHash],
    );
    if (!rows[0]) {
      const again = await loadTeamSession(tx, token, now);
      return again ? { token, ...again } : null;
    }
    const context = await resolveTenantContext(tx, rows[0].user_key, rows[0].tenant_id);
    await requireActiveMember(tx, context);
    return { token: next, session: mapSession(rows[0]), context };
  });
}

export async function revokeTeamSession(sql: TeamSql, token: string, now: Date = new Date()): Promise<void> {
  if (!token) return;
  await sql.query(
    `UPDATE team_session SET revoked_at = $2
     WHERE (token_hash = $1 OR prev_token_hash = $1) AND revoked_at IS NULL`,
    [hashToken(token), now.toISOString()],
  );
}

export function remainingSessionMaxAge(session: TeamSession, now: Date = new Date()): number {
  return Math.max(0, Math.floor((session.expiresAt.getTime() - now.getTime()) / 1000));
}
