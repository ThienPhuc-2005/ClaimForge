import { createHash, timingSafeEqual } from "node:crypto";
import { TeamBootstrapError, TeamIsolationError, TeamValidationError } from "./errors.ts";
import { isTeamRole, type TeamMember, type TeamRole } from "./types.ts";

const TENANT_BRAND = Symbol("claimforge.team.tenant-context");
const BOOTSTRAP_BRAND = Symbol("claimforge.team.bootstrap-actor");

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

const MIN_BOOTSTRAP_SECRET = 16;

function sha256(value: string): Buffer {
  return createHash("sha256").update(value, "utf8").digest();
}

export function secretsMatch(provided: string, configured: string): boolean {
  if (!configured) return false;
  return timingSafeEqual(sha256(provided), sha256(configured));
}

export function unlockBootstrap(provided: string, configured: string): BootstrapActor {
  if (!configured || configured.length < MIN_BOOTSTRAP_SECRET) {
    throw new TeamBootstrapError("bootstrap is not configured");
  }
  if (!secretsMatch(provided, configured)) {
    throw new TeamBootstrapError("bootstrap denied");
  }
  return { [BOOTSTRAP_BRAND]: true, label: "operator" };
}

export function assertBootstrapActor(actor: BootstrapActor): void {
  if (!actor || actor[BOOTSTRAP_BRAND] !== true) {
    throw new TeamBootstrapError("bootstrap requires an operator unlock");
  }
}

export function contextFromMember(member: TeamMember): TenantContext {
  if (!member.tenantId || !member.userKey || !isTeamRole(member.role)) {
    throw new TeamIsolationError("membership row is incomplete");
  }
  return {
    [TENANT_BRAND]: true,
    tenantId: member.tenantId,
    userKey: member.userKey,
    role: member.role,
  };
}

export function assertTenantContext(ctx: TenantContext): void {
  if (!ctx || ctx[TENANT_BRAND] !== true) {
    throw new TeamIsolationError("unverified tenant context");
  }
  if (!ctx.tenantId || !ctx.userKey || !isTeamRole(ctx.role)) {
    throw new TeamIsolationError("unverified tenant context");
  }
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
