import type { AnalysisPolicy } from "../claimforge/policy.ts";
import type { ReviewState } from "../claimforge/types.ts";

export const TEAM_ROLES = ["owner", "admin", "lead", "analyst", "viewer"] as const;
export type TeamRole = (typeof TEAM_ROLES)[number];

export function isTeamRole(value: unknown): value is TeamRole {
  return typeof value === "string" && (TEAM_ROLES as readonly string[]).includes(value);
}

export interface TeamSql {
  query<T = Record<string, unknown>>(text: string, params?: unknown[]): Promise<T[]>;
  transaction<T>(fn: (sql: TeamSql) => Promise<T>): Promise<T>;
}

export interface TeamTenant {
  id: string;
  slug: string;
  name: string;
  bootstrapActor: string;
  createdAt: string;
}

export interface TeamMember {
  tenantId: string;
  userKey: string;
  role: TeamRole;
  createdAt: string;
}

export interface TeamWorkspace {
  tenantId: string;
  id: string;
  name: string;
  createdByUserKey: string;
  createdAt: string;
}

export interface TeamCollab {
  tenantId: string;
  workspaceId: string;
  policy: AnalysisPolicy | null;
  review: Record<string, ReviewState> | null;
  reportDto: unknown | null;
  updatedByUserKey: string;
  updatedAt: string;
}

export interface CollabWrite {
  policy?: AnalysisPolicy | null;
  review?: Record<string, ReviewState> | null;
  reportDto?: unknown | null;
}
