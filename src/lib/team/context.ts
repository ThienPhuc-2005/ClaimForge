import { createHash, randomUUID, timingSafeEqual } from "node:crypto";
import { TeamAmbiguousError, TeamBootstrapError, TeamIsolationError, TeamNotFoundError, TeamValidationError } from "./errors.ts";
import { isTeamRole, type TeamMember, type TeamRole, type TeamSql, type TeamTenant } from "./types.ts";

const TENANT_BRAND = Symbol("claimforge.team.tenant-context");
const BOOTSTRAP_BRAND = Symbol("claimforge.team.bootstrap-actor");

export type BoundIdentity = {
  readonly tenantId: string;
  readonly userKey: string;
  readonly role: TeamRole;
};

export type TenantContext = {
  readonly [TENANT_BRAND]: true;
  readonly tenantId: string;
  readonly userKey: string;
  readonly role: TeamRole;
};

export type BootstrapActor = {
  readonly [BOOTSTRAP_BRAND]: true;
  readonly label: string;
};

type BoundBootstrap = {
  readonly label: string;
};

const issuedContexts = new WeakMap<TenantContext, BoundIdentity>();
const issuedBootstrap = new WeakMap<BootstrapActor, BoundBootstrap>();

const MIN_BOOTSTRAP_SECRET = 16;

function sha256(value: string): Buffer {
  return createHash("sha256").update(value, "utf8").digest();
}

export function secretsMatch(provided: string, configured: string): boolean {
  if (!configured) return false;
  return timingSafeEqual(sha256(provided), sha256(configured));
}

function freezeIdentity(tenantId: string, userKey: string, role: TeamRole): BoundIdentity {
  return Object.freeze({ tenantId, userKey, role });
}

function freezeBootstrap(label: string): BoundBootstrap {
  return Object.freeze({ label });
}

export function unlockBootstrap(provided: string, configured: string): BootstrapActor {
  if (!configured || configured.length < MIN_BOOTSTRAP_SECRET) {
    throw new TeamBootstrapError("bootstrap is not configured");
  }
  if (!secretsMatch(provided, configured)) {
    throw new TeamBootstrapError("bootstrap denied");
  }
  const actor = Object.freeze({
    [BOOTSTRAP_BRAND]: true as const,
    label: "operator",
  }) as BootstrapActor;
  issuedBootstrap.set(actor, freezeBootstrap("operator"));
  return actor;
}

export function assertBootstrapActor(actor: BootstrapActor): void {
  const bound = actor ? issuedBootstrap.get(actor) : undefined;
  if (!actor || actor[BOOTSTRAP_BRAND] !== true || !bound) {
    throw new TeamBootstrapError("bootstrap requires an operator unlock");
  }
  if (actor.label !== bound.label || !bound.label) {
    throw new TeamBootstrapError("bootstrap requires an operator unlock");
  }
}

function boundBootstrap(actor: BootstrapActor): BoundBootstrap {
  assertBootstrapActor(actor);
  const bound = issuedBootstrap.get(actor);
  if (!bound) throw new TeamBootstrapError("bootstrap requires an operator unlock");
  return freezeBootstrap(bound.label);
}

type MemberRow = {
  tenant_id: string;
  user_key: string;
  role: string;
  created_at: string | Date;
};

type TenantRow = {
  id: string;
  slug: string;
  name: string;
  bootstrap_actor: string;
  created_at: string | Date;
};

function stamp(value: string | Date): string {
  return value instanceof Date ? value.toISOString() : String(value);
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

function mapTenant(row: TenantRow): TeamTenant {
  return {
    id: row.id,
    slug: row.slug,
    name: row.name,
    bootstrapActor: row.bootstrap_actor,
    createdAt: stamp(row.created_at),
  };
}

/** Brand a context from a membership row already loaded from SQL. Not exported. */
function tenantContextFromDbRow(member: TeamMember): TenantContext {
  if (!member.tenantId || !member.userKey || !isTeamRole(member.role)) {
    throw new TeamIsolationError("membership row is incomplete");
  }
  const ctx = Object.freeze({
    [TENANT_BRAND]: true as const,
    tenantId: member.tenantId,
    userKey: member.userKey,
    role: member.role,
  }) as TenantContext;
  issuedContexts.set(ctx, freezeIdentity(member.tenantId, member.userKey, member.role));
  return ctx;
}

async function loadMember(sql: TeamSql, tenantId: string, userKey: string): Promise<TeamMember | null> {
  const rows = await sql.query<MemberRow>(
    "SELECT tenant_id, user_key, role, created_at FROM team_member WHERE tenant_id = $1 AND user_key = $2",
    [tenantId, userKey],
  );
  return rows[0] ? mapMember(rows[0]) : null;
}

export function assertTenantContext(ctx: TenantContext): void {
  const bound = ctx ? issuedContexts.get(ctx) : undefined;
  if (!ctx || ctx[TENANT_BRAND] !== true || !bound) {
    throw new TeamIsolationError("unverified tenant context");
  }
  if (
    ctx.tenantId !== bound.tenantId ||
    ctx.userKey !== bound.userKey ||
    ctx.role !== bound.role ||
    !bound.tenantId ||
    !bound.userKey ||
    !isTeamRole(bound.role)
  ) {
    throw new TeamIsolationError("unverified tenant context");
  }
}

/** Frozen snapshot from the mint registry. Never a mutable WeakMap entry. */
function boundIdentity(ctx: TenantContext): BoundIdentity {
  assertTenantContext(ctx);
  const bound = issuedContexts.get(ctx);
  if (!bound) throw new TeamIsolationError("unverified tenant context");
  return freezeIdentity(bound.tenantId, bound.userKey, bound.role);
}

/**
 * Central repository guard: registry identity + live membership SELECT.
 * Role comes from the current member row, not the minted context.
 */
export async function requireActiveMember(sql: TeamSql, ctx: TenantContext): Promise<BoundIdentity> {
  const bound = boundIdentity(ctx);
  const member = await loadMember(sql, bound.tenantId, bound.userKey);
  if (!member) throw new TeamNotFoundError("not found");
  return freezeIdentity(member.tenantId, member.userKey, member.role);
}

/** Reject caller-supplied tenant identifiers on input objects. */
export function rejectCallerTenantId(input: unknown): void {
  if (input == null || typeof input !== "object") return;
  if (Object.prototype.hasOwnProperty.call(input, "tenantId") || Object.prototype.hasOwnProperty.call(input, "tenant_id")) {
    throw new TeamIsolationError("tenant_id is not accepted from caller input");
  }
}

export function requireUserKey(value: unknown): string {
  if (typeof value !== "string") throw new TeamValidationError("user_key is required");
  const key = value.trim();
  if (!key || key.length > 256 || key.includes("\0")) {
    throw new TeamValidationError("user_key is invalid");
  }
  return key;
}

export function requireSlug(value: unknown): string {
  if (typeof value !== "string") throw new TeamValidationError("slug is required");
  const slug = value.trim().toLowerCase();
  if (!/^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?$/.test(slug) || slug.length < 2) {
    throw new TeamValidationError("slug is invalid");
  }
  return slug;
}

export function requireName(value: unknown): string {
  if (typeof value !== "string") throw new TeamValidationError("name is required");
  const name = value.trim();
  if (!name || name.length > 200) throw new TeamValidationError("name is invalid");
  return name;
}

export function requireRole(value: unknown): TeamRole {
  if (!isTeamRole(value)) throw new TeamValidationError("role is invalid");
  return value;
}

export async function bootstrapTenant(
  sql: TeamSql,
  actor: BootstrapActor,
  input: { slug: string; name: string; ownerUserKey: string },
): Promise<{ tenant: TeamTenant; owner: TeamMember; context: TenantContext }> {
  const operator = boundBootstrap(actor);
  rejectCallerTenantId(input);
  const slug = requireSlug(input.slug);
  const name = requireName(input.name);
  const ownerUserKey = requireUserKey(input.ownerUserKey);
  return sql.transaction(async (tx) => {
    const tenantId = randomUUID();
    await tx.query("INSERT INTO team_tenant (id, slug, name, bootstrap_actor) VALUES ($1, $2, $3, $4)", [
      tenantId,
      slug,
      name,
      operator.label,
    ]);
    await tx.query("INSERT INTO team_member (tenant_id, user_key, role) VALUES ($1, $2, $3)", [
      tenantId,
      ownerUserKey,
      "owner",
    ]);
    const tenants = await tx.query<TenantRow>(
      "SELECT id, slug, name, bootstrap_actor, created_at FROM team_tenant WHERE id = $1",
      [tenantId],
    );
    const owner = await loadMember(tx, tenantId, ownerUserKey);
    if (!tenants[0] || !owner) throw new TeamIsolationError("bootstrap did not persist");
    return { tenant: mapTenant(tenants[0]), owner, context: tenantContextFromDbRow(owner) };
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
    return tenantContextFromDbRow(member);
  }
  const rows = await sql.query<MemberRow>(
    "SELECT tenant_id, user_key, role, created_at FROM team_member WHERE user_key = $1",
    [userKey],
  );
  if (rows.length === 0) throw new TeamNotFoundError("not found");
  if (rows.length > 1) throw new TeamAmbiguousError("user belongs to multiple tenants");
  return tenantContextFromDbRow(mapMember(rows[0]!));
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
