import { randomUUID } from "node:crypto";
import { rejectCallerTenantId, requireActiveMember, withActiveMember, type TenantContext } from "./context.ts";
import { TeamIsolationError, TeamPersistError, TeamValidationError } from "./errors.ts";
import { isTeamRole, type TeamRole, type TeamSql } from "./types.ts";

export const AUDIT_ACTIONS = [
  "member.add",
  "member.role",
  "member.remove",
  "workspace.create",
  "workspace.delete",
  "collab.update",
] as const;
export type AuditAction = (typeof AUDIT_ACTIONS)[number];

export const AUDIT_TARGET_KINDS = ["member", "workspace", "collab"] as const;
export type AuditTargetKind = (typeof AUDIT_TARGET_KINDS)[number];

export const AUDIT_LIST_MAX = 200;
export const AUDIT_DETAIL_MAX_BYTES = 4096;

const FORBIDDEN_DETAIL_KEYS = new Set([
  "ip",
  "iphash",
  "ip_hash",
  "clientip",
  "client_ip",
  "useragent",
  "user_agent",
  "ua",
  "jwt",
  "jwks",
  "token",
  "cookie",
  "har",
  "raw",
  "capture",
  "araw",
  "braw",
  "actor",
  "actoruserkey",
  "actor_user_key",
  "actorrole",
  "actor_role",
  "tenantid",
  "tenant_id",
  "authorization",
  "n",
  "e",
  "kty",
]);

const COMPACT_JWT = /eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*/;
const JWKS_SHAPE = /"kty"\s*:|"x5c"\s*:|"n"\s*:\s*"[A-Za-z0-9_-]{20,}/;

export type AuditDetail = Record<string, unknown>;

export type AuditWrite = {
  action: AuditAction;
  targetKind: AuditTargetKind;
  targetId: string;
  detail: AuditDetail;
};

export type TeamAuditEvent = {
  id: string;
  tenantId: string;
  at: string;
  actorUserKey: string;
  actorRole: TeamRole;
  action: AuditAction;
  targetKind: AuditTargetKind;
  targetId: string;
  detail: AuditDetail;
};

type AuditRow = {
  id: string;
  tenant_id: string;
  at: string | Date;
  actor_user_key: string;
  actor_role: string;
  action: string;
  target_kind: string;
  target_id: string;
  detail_json: string;
};

const SPOOF_KEYS = [
  "actor",
  "actorUserKey",
  "actor_user_key",
  "actorRole",
  "actor_role",
  "ip",
  "ipHash",
  "ip_hash",
  "userAgent",
  "user_agent",
] as const;

/** Caller must not choose the actor, IP, or UA. Live membership is the only actor. */
export function rejectCallerAuditSpoof(input: unknown): void {
  if (input == null || typeof input !== "object") return;
  for (const key of SPOOF_KEYS) {
    if (Object.prototype.hasOwnProperty.call(input, key)) {
      throw new TeamIsolationError("actor identity is not accepted from caller input");
    }
  }
}

function isAuditAction(value: string): value is AuditAction {
  return (AUDIT_ACTIONS as readonly string[]).includes(value);
}

function isAuditTargetKind(value: string): value is AuditTargetKind {
  return (AUDIT_TARGET_KINDS as readonly string[]).includes(value);
}

function utf8Bytes(value: string): number {
  return Buffer.byteLength(value, "utf8");
}

function requireTargetId(value: string): string {
  if (!value || value.length > 256 || value.includes("\0")) {
    throw new TeamValidationError("audit target is invalid");
  }
  return value;
}

function assertNoForbiddenKeys(detail: Record<string, unknown>): void {
  for (const key of Object.keys(detail)) {
    const folded = key.toLowerCase().replace(/-/g, "_");
    if (FORBIDDEN_DETAIL_KEYS.has(folded) || FORBIDDEN_DETAIL_KEYS.has(key.toLowerCase())) {
      throw new TeamPersistError("audit detail is not allowed");
    }
  }
}

function assertNoSecrets(value: unknown): void {
  if (typeof value === "string") {
    if (COMPACT_JWT.test(value) || JWKS_SHAPE.test(value) || value.includes("-----BEGIN")) {
      throw new TeamPersistError("audit detail is not allowed");
    }
    return;
  }
  if (Array.isArray(value)) {
    for (const item of value) assertNoSecrets(item);
    return;
  }
  if (value && typeof value === "object") {
    assertNoForbiddenKeys(value as Record<string, unknown>);
    for (const nested of Object.values(value)) assertNoSecrets(nested);
  }
}

function expectRole(value: unknown, label: string): TeamRole {
  if (!isTeamRole(value)) throw new TeamValidationError(`${label} is invalid`);
  return value;
}

/** Closed detail shapes. Never persist collab bodies, JWKS, IP, or UA. */
export function assertAuditDetail(action: AuditAction, detail: unknown): AuditDetail {
  if (detail == null || typeof detail !== "object" || Array.isArray(detail)) {
    throw new TeamValidationError("audit detail is invalid");
  }
  const rec = detail as Record<string, unknown>;
  assertNoForbiddenKeys(rec);
  assertNoSecrets(rec);
  let allowed: AuditDetail;
  switch (action) {
    case "member.add":
    case "member.remove": {
      const keys = Object.keys(rec);
      if (keys.length !== 1 || keys[0] !== "role") throw new TeamValidationError("audit detail is invalid");
      allowed = { role: expectRole(rec.role, "role") };
      break;
    }
    case "member.role": {
      const keys = Object.keys(rec).sort();
      if (keys.length !== 2 || keys[0] !== "fromRole" || keys[1] !== "toRole") {
        throw new TeamValidationError("audit detail is invalid");
      }
      allowed = {
        fromRole: expectRole(rec.fromRole, "fromRole"),
        toRole: expectRole(rec.toRole, "toRole"),
      };
      break;
    }
    case "workspace.create": {
      const keys = Object.keys(rec);
      if (keys.length !== 1 || keys[0] !== "name") throw new TeamValidationError("audit detail is invalid");
      if (typeof rec.name !== "string" || !rec.name || rec.name.length > 200) {
        throw new TeamValidationError("audit detail is invalid");
      }
      allowed = { name: rec.name };
      break;
    }
    case "workspace.delete": {
      if (Object.keys(rec).length !== 0) throw new TeamValidationError("audit detail is invalid");
      allowed = {};
      break;
    }
    case "collab.update": {
      const keys = Object.keys(rec);
      if (keys.length !== 1 || keys[0] !== "fields") throw new TeamValidationError("audit detail is invalid");
      if (!Array.isArray(rec.fields) || rec.fields.length === 0 || rec.fields.length > 3) {
        throw new TeamValidationError("audit detail is invalid");
      }
      const allowedFields = new Set(["policy", "review", "report"]);
      const fields: string[] = [];
      for (const field of rec.fields) {
        if (typeof field !== "string" || !allowedFields.has(field) || fields.includes(field)) {
          throw new TeamValidationError("audit detail is invalid");
        }
        fields.push(field);
      }
      allowed = { fields };
      break;
    }
    default: {
      const _never: never = action;
      throw new TeamValidationError(`audit action is invalid: ${_never}`);
    }
  }
  const json = JSON.stringify(allowed);
  if (utf8Bytes(json) > AUDIT_DETAIL_MAX_BYTES) throw new TeamPersistError("audit detail is not allowed");
  return allowed;
}

function expectedTargetKind(action: AuditAction): AuditTargetKind {
  if (action.startsWith("member.")) return "member";
  if (action.startsWith("workspace.")) return "workspace";
  return "collab";
}

function mapEvent(row: AuditRow): TeamAuditEvent {
  if (!isAuditAction(row.action) || !isAuditTargetKind(row.target_kind) || !isTeamRole(row.actor_role)) {
    throw new TeamIsolationError("audit row is incomplete");
  }
  let detail: unknown;
  try {
    detail = JSON.parse(row.detail_json) as unknown;
  } catch {
    throw new TeamPersistError("audit detail is not allowed");
  }
  return {
    id: row.id,
    tenantId: row.tenant_id,
    at: row.at instanceof Date ? row.at.toISOString() : String(row.at),
    actorUserKey: row.actor_user_key,
    actorRole: row.actor_role,
    action: row.action,
    targetKind: row.target_kind,
    targetId: row.target_id,
    detail: assertAuditDetail(row.action, detail),
  };
}

/**
 * Insert one audit row. Actor is the live `team_member` row (re-SELECT), never
 * a client-supplied id, JWT role, or minted `ctx.role`.
 */
export async function appendAuditEvent(sql: TeamSql, ctx: TenantContext, write: AuditWrite): Promise<TeamAuditEvent> {
  const ident = await requireActiveMember(sql, ctx);
  rejectCallerTenantId(write);
  rejectCallerAuditSpoof(write);
  if (write.targetKind !== expectedTargetKind(write.action)) {
    throw new TeamValidationError("audit target is invalid");
  }
  const targetId = requireTargetId(write.targetId);
  const detail = assertAuditDetail(write.action, write.detail);
  const id = randomUUID();
  const rows = await sql.query<AuditRow>(
    `INSERT INTO team_audit (
      id, tenant_id, actor_user_key, actor_role, action, target_kind, target_id, detail_json
    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
    RETURNING id, tenant_id, at, actor_user_key, actor_role, action, target_kind, target_id, detail_json`,
    [id, ident.tenantId, ident.userKey, ident.role, write.action, write.targetKind, targetId, JSON.stringify(detail)],
  );
  if (!rows[0]) throw new TeamIsolationError("audit did not persist");
  return mapEvent(rows[0]);
}

export async function listAudit(
  sql: TeamSql,
  ctx: TenantContext,
  input: { limit?: number } = {},
): Promise<TeamAuditEvent[]> {
  return withActiveMember(sql, ctx, async (tx, ident) => {
    rejectCallerTenantId(input);
    rejectCallerAuditSpoof(input);
    const limit =
      input.limit === undefined
        ? 100
        : Number.isInteger(input.limit) && input.limit >= 1 && input.limit <= AUDIT_LIST_MAX
          ? input.limit
          : (() => {
              throw new TeamValidationError("audit limit is invalid");
            })();
    const rows = await tx.query<AuditRow>(
      `SELECT id, tenant_id, at, actor_user_key, actor_role, action, target_kind, target_id, detail_json
     FROM team_audit
     WHERE tenant_id = $1
     ORDER BY at DESC, id DESC
     LIMIT $2`,
      [ident.tenantId, limit],
    );
    return rows.map(mapEvent);
  });
}
