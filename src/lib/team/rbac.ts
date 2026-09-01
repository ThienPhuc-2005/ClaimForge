import { TeamForbiddenError } from "./errors.ts";
import type { TeamRole } from "./types.ts";

/** Higher number is more privileged. Live `team_member.role` is the only authority. */
export const TEAM_ROLE_RANK: Record<TeamRole, number> = {
  viewer: 1,
  analyst: 2,
  lead: 3,
  admin: 4,
  owner: 5,
};

export type TeamCapability = "read" | "mutateWorkspace" | "acceptRisk" | "manageMembers";

const MIN_RANK: Record<TeamCapability, number> = {
  read: TEAM_ROLE_RANK.viewer,
  mutateWorkspace: TEAM_ROLE_RANK.analyst,
  acceptRisk: TEAM_ROLE_RANK.lead,
  manageMembers: TEAM_ROLE_RANK.admin,
};

export function roleRank(role: TeamRole): number {
  return TEAM_ROLE_RANK[role];
}

export function hasCapability(role: TeamRole, capability: TeamCapability): boolean {
  return roleRank(role) >= MIN_RANK[capability];
}

export function assertCapability(role: TeamRole, capability: TeamCapability): void {
  if (!hasCapability(role, capability)) throw new TeamForbiddenError("forbidden");
}

/** Second owner is bootstrap-only. HTTP/repo cannot assign `owner`. */
export function canAssignRole(actor: TeamRole, assigned: TeamRole): boolean {
  if (assigned === "owner") return false;
  return roleRank(assigned) < roleRank(actor);
}

export function assertCanAssignRole(actor: TeamRole, assigned: TeamRole): void {
  if (!canAssignRole(actor, assigned)) throw new TeamForbiddenError("forbidden");
}

/**
 * Admin manages strictly lower ranks. Owner may manage any member except as
 * constrained by last-owner checks in the repository.
 */
export function canManageTarget(actor: TeamRole, target: TeamRole): boolean {
  if (actor === "owner") return true;
  return roleRank(target) < roleRank(actor);
}

export function assertCanManageTarget(actor: TeamRole, target: TeamRole): void {
  if (!canManageTarget(actor, target)) throw new TeamForbiddenError("forbidden");
}

export function reviewIncludesAcceptedRisk(
  review: Record<string, string> | null | undefined,
): boolean {
  if (!review) return false;
  return Object.values(review).some((state) => state === "accepted-risk");
}
