import { randomUUID } from "node:crypto";
import {
  assertBootstrapActor,
  assertTenantContext,
  contextFromMember,
  rejectCallerTenantId,
  requireName,
  requireRole,
  requireSlug,
  requireUserKey,
  type BootstrapActor,
  type TenantContext,
} from "./context.ts";
import {
  TeamAmbiguousError,
  TeamIsolationError,
  TeamNotFoundError,
  TeamValidationError,
} from "./errors.ts";
import { assertAllowedCollab } from "./persist-guard.ts";
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

function parseJson<T>(raw: string | null): T | null {
  if (raw == null) return null;
  return JSON.parse(raw) as T;
}

function mapCollab(row: CollabRow): TeamCollab {
  return {
    tenantId: row.tenant_id,
    workspaceId: row.workspace_id,
    policy: parseJson(row.policy_json),
    review: parseJson(row.review_json),
    reportDto: parseJson(row.report_dto_json),
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

export async function bootstrapTenant(
  sql: TeamSql,
  actor: BootstrapActor,
  input: { slug: string; name: string; ownerUserKey: string },
): Promise<{ tenant: TeamTenant; owner: TeamMember; context: TenantContext }> {
  assertBootstrapActor(actor);
  rejectCallerTenantId(input);
  const slug = requireSlug(input.slug);
  const name = requireName(input.name);
  const ownerUserKey = requireUserKey(input.ownerUserKey);
  return sql.transaction(async (tx) => {
    const tenantId = randomUUID();
    await tx.query(
      "INSERT INTO team_tenant (id, slug, name, bootstrap_actor) VALUES ($1, $2, $3, $4)",
      [tenantId, slug, name, actor.label],
    );
    await tx.query(
      "INSERT INTO team_member (tenant_id, user_key, role) VALUES ($1, $2, $3)",
      [tenantId, ownerUserKey, "owner"],
    );
    const tenants = await tx.query<TenantRow>(
      "SELECT id, slug, name, bootstrap_actor, created_at FROM team_tenant WHERE id = $1",
      [tenantId],
    );
    const owner = await loadMember(tx, tenantId, ownerUserKey);
    if (!tenants[0] || !owner) throw new TeamIsolationError("bootstrap did not persist");
    return { tenant: mapTenant(tenants[0]), owner, context: contextFromMember(owner) };
  });
}

export async function resolveTenantContext(
  sql: TeamSql,
  userKeyRaw: string,
  requestedTenantId?: string,
): Promise<TenantContext> {
  const userKey = requireUserKey(userKeyRaw);
  if (requestedTenantId !== undefined) {
    if (typeof requestedTenantId !== "string" || !requestedTenantId.trim()) {
      throw new TeamNotFoundError("not found");
    }
    const member = await loadMember(sql, requestedTenantId.trim(), userKey);
    if (!member) throw new TeamNotFoundError("not found");
    return contextFromMember(member);
  }
  const rows = await sql.query<MemberRow>(
    "SELECT tenant_id, user_key, role, created_at FROM team_member WHERE user_key = $1",
    [userKey],
  );
  if (rows.length === 0) throw new TeamNotFoundError("not found");
  if (rows.length > 1) throw new TeamAmbiguousError("user belongs to multiple tenants");
  return contextFromMember(mapMember(rows[0]!));
}

export async function resolveTenantContextBySlug(
  sql: TeamSql,
  userKeyRaw: string,
  slugRaw: string,
): Promise<TenantContext> {
  const slug = requireSlug(slugRaw);
  const tenants = await sql.query<{ id: string }>("SELECT id FROM team_tenant WHERE slug = $1", [slug]);
  if (!tenants[0]) throw new TeamNotFoundError("not found");
  return resolveTenantContext(sql, userKeyRaw, tenants[0].id);
}

export async function getTenant(sql: TeamSql, ctx: TenantContext): Promise<TeamTenant> {
  assertTenantContext(ctx);
  const rows = await sql.query<TenantRow>(
    "SELECT id, slug, name, bootstrap_actor, created_at FROM team_tenant WHERE id = $1",
    [ctx.tenantId],
  );
  if (!rows[0]) throw new TeamNotFoundError("not found");
  return mapTenant(rows[0]);
}

export async function listMembers(sql: TeamSql, ctx: TenantContext): Promise<TeamMember[]> {
  assertTenantContext(ctx);
  const rows = await sql.query<MemberRow>(
    "SELECT tenant_id, user_key, role, created_at FROM team_member WHERE tenant_id = $1 ORDER BY user_key",
    [ctx.tenantId],
  );
  return rows.map(mapMember);
}

export async function addMember(
  sql: TeamSql,
  ctx: TenantContext,
  input: { userKey: string; role: TeamRole },
): Promise<TeamMember> {
  assertTenantContext(ctx);
  rejectCallerTenantId(input);
  const userKey = requireUserKey(input.userKey);
  const role = requireRole(input.role);
  try {
    await sql.query("INSERT INTO team_member (tenant_id, user_key, role) VALUES ($1, $2, $3)", [
      ctx.tenantId,
      userKey,
      role,
    ]);
  } catch (err) {
    const code = (err as { code?: string }).code;
    if (code === "23505") throw new TeamValidationError("member already exists");
    throw err;
  }
  const member = await loadMember(sql, ctx.tenantId, userKey);
  if (!member) throw new TeamNotFoundError("not found");
  return member;
}

export async function createWorkspace(
  sql: TeamSql,
  ctx: TenantContext,
  input: { name: string },
): Promise<TeamWorkspace> {
  assertTenantContext(ctx);
  rejectCallerTenantId(input);
  const name = requireName(input.name);
  const id = randomUUID();
  await sql.query(
    "INSERT INTO team_workspace (tenant_id, id, name, created_by_user_key) VALUES ($1, $2, $3, $4)",
    [ctx.tenantId, id, name, ctx.userKey],
  );
  const rows = await sql.query<WorkspaceRow>(
    "SELECT tenant_id, id, name, created_by_user_key, created_at FROM team_workspace WHERE tenant_id = $1 AND id = $2",
    [ctx.tenantId, id],
  );
  if (!rows[0]) throw new TeamNotFoundError("not found");
  return mapWorkspace(rows[0]);
}

async function loadWorkspace(sql: TeamSql, ctx: TenantContext, workspaceId: string): Promise<TeamWorkspace> {
  assertTenantContext(ctx);
  if (!workspaceId) throw new TeamNotFoundError("not found");
  const rows = await sql.query<WorkspaceRow>(
    "SELECT tenant_id, id, name, created_by_user_key, created_at FROM team_workspace WHERE tenant_id = $1 AND id = $2",
    [ctx.tenantId, workspaceId],
  );
  if (!rows[0]) throw new TeamNotFoundError("not found");
  return mapWorkspace(rows[0]);
}

export async function getWorkspace(sql: TeamSql, ctx: TenantContext, workspaceId: string): Promise<TeamWorkspace> {
  return loadWorkspace(sql, ctx, workspaceId);
}

export async function listWorkspaces(sql: TeamSql, ctx: TenantContext): Promise<TeamWorkspace[]> {
  assertTenantContext(ctx);
  const rows = await sql.query<WorkspaceRow>(
    "SELECT tenant_id, id, name, created_by_user_key, created_at FROM team_workspace WHERE tenant_id = $1 ORDER BY created_at",
    [ctx.tenantId],
  );
  return rows.map(mapWorkspace);
}

export async function deleteWorkspace(sql: TeamSql, ctx: TenantContext, workspaceId: string): Promise<void> {
  assertTenantContext(ctx);
  const rows = await sql.query<{ id: string }>(
    "DELETE FROM team_workspace WHERE tenant_id = $1 AND id = $2 RETURNING id",
    [ctx.tenantId, workspaceId],
  );
  if (!rows[0]) throw new TeamNotFoundError("not found");
}

export async function getCollab(sql: TeamSql, ctx: TenantContext, workspaceId: string): Promise<TeamCollab | null> {
  await loadWorkspace(sql, ctx, workspaceId);
  const rows = await sql.query<CollabRow>(
    "SELECT tenant_id, workspace_id, policy_json, review_json, report_dto_json, updated_by_user_key, updated_at FROM team_workspace_collab WHERE tenant_id = $1 AND workspace_id = $2",
    [ctx.tenantId, workspaceId],
  );
  return rows[0] ? mapCollab(rows[0]) : null;
}

export async function updateWorkspaceCollab(
  sql: TeamSql,
  ctx: TenantContext,
  workspaceId: string,
  write: CollabWrite,
): Promise<TeamCollab> {
  assertTenantContext(ctx);
  rejectCallerTenantId(write);
  await loadWorkspace(sql, ctx, workspaceId);
  const safe = assertAllowedCollab(write);
  const policyJson = safe.policy === undefined ? undefined : safe.policy === null ? null : JSON.stringify(safe.policy);
  const reviewJson = safe.review === undefined ? undefined : safe.review === null ? null : JSON.stringify(safe.review);
  const reportJson =
    safe.reportDto === undefined ? undefined : safe.reportDto === null ? null : JSON.stringify(safe.reportDto);

  const existing = await sql.query<CollabRow>(
    "SELECT tenant_id, workspace_id, policy_json, review_json, report_dto_json, updated_by_user_key, updated_at FROM team_workspace_collab WHERE tenant_id = $1 AND workspace_id = $2",
    [ctx.tenantId, workspaceId],
  );
  const prev = existing[0];
  const nextPolicy = policyJson === undefined ? (prev?.policy_json ?? null) : policyJson;
  const nextReview = reviewJson === undefined ? (prev?.review_json ?? null) : reviewJson;
  const nextReport = reportJson === undefined ? (prev?.report_dto_json ?? null) : reportJson;
  if (!prev) {
    await sql.query(
      "INSERT INTO team_workspace_collab (tenant_id, workspace_id, policy_json, review_json, report_dto_json, updated_by_user_key) VALUES ($1, $2, $3, $4, $5, $6)",
      [ctx.tenantId, workspaceId, nextPolicy, nextReview, nextReport, ctx.userKey],
    );
  } else {
    await sql.query(
      `UPDATE team_workspace_collab SET
        policy_json = $3,
        review_json = $4,
        report_dto_json = $5,
        updated_by_user_key = $6,
        updated_at = CURRENT_TIMESTAMP
      WHERE tenant_id = $1 AND workspace_id = $2`,
      [ctx.tenantId, workspaceId, nextPolicy, nextReview, nextReport, ctx.userKey],
    );
  }
  const rows = await sql.query<CollabRow>(
    "SELECT tenant_id, workspace_id, policy_json, review_json, report_dto_json, updated_by_user_key, updated_at FROM team_workspace_collab WHERE tenant_id = $1 AND workspace_id = $2",
    [ctx.tenantId, workspaceId],
  );
  if (!rows[0]) throw new TeamNotFoundError("not found");
  return mapCollab(rows[0]);
}
