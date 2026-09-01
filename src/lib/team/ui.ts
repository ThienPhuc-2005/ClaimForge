import { canAssignRole, hasCapability, reviewIncludesAcceptedRisk } from "./rbac.ts";
import { TEAM_ROLES, type TeamRole } from "./types.ts";

/** ADR-027 — shown on the Team inspect view. */
export const TEAM_LOOT_LOCAL_COPY =
  "Team stores policy, review, and a redacted report. Loot and replay copy in this tab is a local analyst action — the server does not control it.";

const SLUG_RE = /^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?$/;

export function isTeamSlug(value: string): boolean {
  const slug = value.trim().toLowerCase();
  return slug.length >= 2 && slug.length <= 64 && SLUG_RE.test(slug);
}

/** Login is slug-only. Never a tenant list and never tenant_id. */
export function teamLoginPath(slug: string): string {
  const trimmed = slug.trim().toLowerCase();
  const params = new URLSearchParams();
  params.set("slug", trimmed);
  return `/api/team/oidc/login?${params.toString()}`;
}

export function payloadHasTenantSpoof(payload: unknown): boolean {
  if (payload == null || typeof payload !== "object") return false;
  return Object.prototype.hasOwnProperty.call(payload, "tenantId") || Object.prototype.hasOwnProperty.call(payload, "tenant_id");
}

export function publicSession(body: unknown): { userKey: string; tenantId: string } | null {
  if (body == null || typeof body !== "object" || Array.isArray(body)) return null;
  const rec = body as Record<string, unknown>;
  if (typeof rec.userKey !== "string" || typeof rec.tenantId !== "string") return null;
  if (!rec.userKey || !rec.tenantId) return null;
  return { userKey: rec.userKey, tenantId: rec.tenantId };
}

export function liveRoleFromMembers(
  userKey: string,
  members: Array<{ userKey: string; role: string }>,
): TeamRole | null {
  const row = members.find((m) => m.userKey === userKey);
  if (!row || !(TEAM_ROLES as readonly string[]).includes(row.role)) return null;
  return row.role as TeamRole;
}

export function assignableRoles(actor: TeamRole): TeamRole[] {
  return TEAM_ROLES.filter((role) => canAssignRole(actor, role));
}

export function memberWritePayload(userKey: string, role: TeamRole): { userKey: string; role: TeamRole } {
  return { userKey, role };
}

export function workspaceWritePayload(name: string): { name: string } {
  return { name };
}

export function collabWritePayload(input: {
  workspaceId: string;
  policy?: unknown;
  review?: unknown;
  reportDto?: unknown;
}): Record<string, unknown> {
  const out: Record<string, unknown> = { workspaceId: input.workspaceId };
  if ("policy" in input) out.policy = input.policy;
  if ("review" in input) out.review = input.review;
  if ("reportDto" in input) out.reportDto = input.reportDto;
  return out;
}

export function canPushAcceptedRisk(role: TeamRole | null, review: Record<string, string> | null | undefined): boolean {
  if (!reviewIncludesAcceptedRisk(review)) return true;
  return role != null && hasCapability(role, "acceptRisk");
}

export { hasCapability, canAssignRole };
