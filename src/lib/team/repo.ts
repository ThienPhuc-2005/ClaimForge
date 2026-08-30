import { randomUUID } from "node:crypto";
import {
  rejectCallerTenantId,
  requireActiveMember,
  requireName,
  requireRole,
  requireUserKey,
  type BoundIdentity,
  type TenantContext,
} from "./context.ts";
import { TeamIsolationError, TeamNotFoundError, TeamValidationError } from "./errors.ts";
import {
  assertAllowedCollab,
  parseStoredPolicy,
  parseStoredReportDto,
  parseStoredReview,
} from "./persist-guard.ts";
import type {
  CollabWrite,
  TeamCollab,
  TeamMember,
  TeamRole,
  TeamSql,
  TeamTenant,
  TeamWorkspace,
} from "./types.ts";
import { isTeamRole } from "./types.ts";

export {
  bootstrapTenant,
  resolveTenantContext,
  resolveTenantContextBySlug,
} from "./context.ts";

type TenantRow = {
  id: string;
  slug: string;
  name: string;
  bootstrap_actor: string;
  created_at: string | Date;
};

type MemberRow = {
  tenant_id: string;
  user_key: string;
  role: string;
  created_at: string | Date;
};

type WorkspaceRow = {
  tenant_id: string;
  id: string;
  name: string;
  created_by_user_key: string;
  created_at: string | Date;
};

type CollabRow = {
  tenant_id: string;
  workspace_id: string;
  policy_json: string | null;
  review_json: string | null;
  report_dto_json: string | null;
  updated_by_user_key: string;
  updated_at: string | Date;
};

function stamp(value: string | Date): string {
  return value instanceof Date ? value.toISOString() : String(value);
}

function mapTenant(row: TenantRow): TeamTenant {
  return {
    id: row.id,
    slug: row.slug,
    name: row.name,
    bootstrapActor: row.bootstrap_actor,
    createdAt: stamp(row.created_at),
  };
}

function mapMember(row: MemberRow): TeamMember {
  if (!isTeamRole(row.role)) throw new TeamIsolationError("membership row is incomplete");
  return {
    tenantId: row.tenant_id,
    userKey: row.user_key,
    role: row.role,
    createdAt: stamp(row.created_at),
  };
}

function mapWorkspace(row: WorkspaceRow): TeamWorkspace {
  return {
    tenantId: row.tenant_id,
    id: row.id,
    name: row.name,
    createdByUserKey: row.created_by_user_key,
    createdAt: stamp(row.created_at),
  };
}

function mapCollab(row: CollabRow): TeamCollab {
  return {
    tenantId: row.tenant_id,
    workspaceId: row.workspace_id,
    policy: parseStoredPolicy(row.policy_json),
    review: parseStoredReview(row.review_json),
    reportDto: parseStoredReportDto(row.report_dto_json),
    updatedByUserKey: row.updated_by_user_key,
    updatedAt: stamp(row.updated_at),
  };
}

async function loadMember(sql: TeamSql, tenantId: string, userKey: string): Promise<TeamMember | null> {
  const rows = await sql.query<MemberRow>(
    "SELECT tenant_id, user_key, role, created_at FROM team_member WHERE tenant_id = $1 AND user_key = $2",
    [tenantId, userKey],
  );
  return rows[0] ? mapMember(rows[0]) : null;
}

export async function getTenant(sql: TeamSql, ctx: TenantContext): Promise<TeamTenant> {
  const ident = await requireActiveMember(sql, ctx);
  const rows = await sql.query<TenantRow>(
    "SELECT id, slug, name, bootstrap_actor, created_at FROM team_tenant WHERE id = $1",
    [ident.tenantId],
  );
  if (!rows[0]) throw new TeamNotFoundError("not found");
  return mapTenant(rows[0]);
}

export async function listMembers(sql: TeamSql, ctx: TenantContext): Promise<TeamMember[]> {
  const ident = await requireActiveMember(sql, ctx);
  const rows = await sql.query<MemberRow>(
    "SELECT tenant_id, user_key, role, created_at FROM team_member WHERE tenant_id = $1 ORDER BY user_key",
    [ident.tenantId],
  );
  return rows.map(mapMember);
}

export async function addMember(
  sql: TeamSql,
  ctx: TenantContext,
  input: { userKey: string; role: TeamRole },
): Promise<TeamMember> {
  const ident = await requireActiveMember(sql, ctx);
  rejectCallerTenantId(input);
  const userKey = requireUserKey(input.userKey);
  const role = requireRole(input.role);
  try {
    await sql.query("INSERT INTO team_member (tenant_id, user_key, role) VALUES ($1, $2, $3)", [
      ident.tenantId,
      userKey,
      role,
    ]);
  } catch (err) {
    const code = (err as { code?: string }).code;
    if (code === "23505") throw new TeamValidationError("member already exists");
    throw err;
  }
  const member = await loadMember(sql, ident.tenantId, userKey);
  if (!member) throw new TeamNotFoundError("not found");
  return member;
}

export async function createWorkspace(
  sql: TeamSql,
  ctx: TenantContext,
  input: { name: string },
): Promise<TeamWorkspace> {
  const ident = await requireActiveMember(sql, ctx);
  rejectCallerTenantId(input);
  const name = requireName(input.name);
  const id = randomUUID();
  await sql.query(
    "INSERT INTO team_workspace (tenant_id, id, name, created_by_user_key) VALUES ($1, $2, $3, $4)",
    [ident.tenantId, id, name, ident.userKey],
  );
  const rows = await sql.query<WorkspaceRow>(
    "SELECT tenant_id, id, name, created_by_user_key, created_at FROM team_workspace WHERE tenant_id = $1 AND id = $2",
    [ident.tenantId, id],
  );
  if (!rows[0]) throw new TeamNotFoundError("not found");
  return mapWorkspace(rows[0]);
}

async function loadWorkspace(sql: TeamSql, ident: BoundIdentity, workspaceId: string): Promise<TeamWorkspace> {
  if (!workspaceId) throw new TeamNotFoundError("not found");
  const rows = await sql.query<WorkspaceRow>(
    "SELECT tenant_id, id, name, created_by_user_key, created_at FROM team_workspace WHERE tenant_id = $1 AND id = $2",
    [ident.tenantId, workspaceId],
  );
  if (!rows[0]) throw new TeamNotFoundError("not found");
  return mapWorkspace(rows[0]);
}

export async function getWorkspace(sql: TeamSql, ctx: TenantContext, workspaceId: string): Promise<TeamWorkspace> {
  const ident = await requireActiveMember(sql, ctx);
  return loadWorkspace(sql, ident, workspaceId);
}

export async function listWorkspaces(sql: TeamSql, ctx: TenantContext): Promise<TeamWorkspace[]> {
  const ident = await requireActiveMember(sql, ctx);
  const rows = await sql.query<WorkspaceRow>(
    "SELECT tenant_id, id, name, created_by_user_key, created_at FROM team_workspace WHERE tenant_id = $1 ORDER BY created_at",
    [ident.tenantId],
  );
  return rows.map(mapWorkspace);
}

export async function deleteWorkspace(sql: TeamSql, ctx: TenantContext, workspaceId: string): Promise<void> {
  const ident = await requireActiveMember(sql, ctx);
  const rows = await sql.query<{ id: string }>(
    "DELETE FROM team_workspace WHERE tenant_id = $1 AND id = $2 RETURNING id",
    [ident.tenantId, workspaceId],
  );
  if (!rows[0]) throw new TeamNotFoundError("not found");
}

export async function getCollab(sql: TeamSql, ctx: TenantContext, workspaceId: string): Promise<TeamCollab | null> {
  const ident = await requireActiveMember(sql, ctx);
  await loadWorkspace(sql, ident, workspaceId);
  const rows = await sql.query<CollabRow>(
    "SELECT tenant_id, workspace_id, policy_json, review_json, report_dto_json, updated_by_user_key, updated_at FROM team_workspace_collab WHERE tenant_id = $1 AND workspace_id = $2",
    [ident.tenantId, workspaceId],
  );
  return rows[0] ? mapCollab(rows[0]) : null;
}

export async function updateWorkspaceCollab(
  sql: TeamSql,
  ctx: TenantContext,
  workspaceId: string,
  write: CollabWrite,
): Promise<TeamCollab> {
  const ident = await requireActiveMember(sql, ctx);
  rejectCallerTenantId(write);
  const safe = assertAllowedCollab(write);
  await loadWorkspace(sql, ident, workspaceId);
  const touchPolicy = safe.policy !== undefined;
  const touchReview = safe.review !== undefined;
  const touchReport = safe.reportDto !== undefined;
  const policyJson = touchPolicy ? (safe.policy === null ? null : JSON.stringify(safe.policy)) : null;
  const reviewJson = touchReview ? (safe.review === null ? null : JSON.stringify(safe.review)) : null;
  const reportJson = touchReport ? (safe.reportDto === null ? null : JSON.stringify(safe.reportDto)) : null;

  const rows = await sql.query<CollabRow>(
    `INSERT INTO team_workspace_collab (
      tenant_id, workspace_id, policy_json, review_json, report_dto_json, updated_by_user_key
    ) VALUES ($1, $2, $3, $4, $5, $6)
    ON CONFLICT (tenant_id, workspace_id) DO UPDATE SET
      policy_json = CASE WHEN $7 THEN EXCLUDED.policy_json ELSE team_workspace_collab.policy_json END,
      review_json = CASE WHEN $8 THEN EXCLUDED.review_json ELSE team_workspace_collab.review_json END,
      report_dto_json = CASE WHEN $9 THEN EXCLUDED.report_dto_json ELSE team_workspace_collab.report_dto_json END,
      updated_by_user_key = EXCLUDED.updated_by_user_key,
      updated_at = CURRENT_TIMESTAMP
    RETURNING tenant_id, workspace_id, policy_json, review_json, report_dto_json, updated_by_user_key, updated_at`,
    [
      ident.tenantId,
      workspaceId,
      policyJson,
      reviewJson,
      reportJson,
      ident.userKey,
      touchPolicy,
      touchReview,
      touchReport,
    ],
  );
  if (!rows[0]) throw new TeamNotFoundError("not found");
  return mapCollab(rows[0]);
}
