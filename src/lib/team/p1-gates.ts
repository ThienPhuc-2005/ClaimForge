/**
 * P1.1 catalog: each isolation invariant has a test that would fail if the kernel is reverted.
 */
export const P1_ITEMS = ["P1.1"] as const;
export type P1Item = (typeof P1_ITEMS)[number];

export interface P1Gate {
  id: string;
  p1: P1Item;
  bug: string;
  before: string;
  after: string;
  evidenceTest: string;
}

export const P1_GATES: P1Gate[] = [
  {
    id: "P1.1-forged-context",
    p1: "P1.1",
    bug: "Plain {tenantId,userKey,role} treated as verified context",
    before: "Caller-built object scoped queries",
    after: "Missing brand is TeamIsolationError",
    evidenceTest: "p1-isolation.test.ts:forged TenantContext without brand is rejected",
  },
  {
    id: "P1.1-caller-tenant-id",
    p1: "P1.1",
    bug: "tenant_id taken from body/input",
    before: "createWorkspace({ tenantId: victim }) wrote into victim",
    after: "Caller tenantId is rejected; SQL uses ctx.tenantId",
    evidenceTest: "p1-isolation.test.ts:caller-supplied tenantId on input is rejected",
  },
  {
    id: "P1.1-cross-tenant-read",
    p1: "P1.1",
    bug: "Knowing a workspace UUID reads another tenant",
    before: "getWorkspace(ctxB, idA) returned A's workspace",
    after: "Cross-tenant read is not-found",
    evidenceTest: "p1-isolation.test.ts:cross-tenant read is not-found",
  },
  {
    id: "P1.1-cross-tenant-update",
    p1: "P1.1",
    bug: "Collab write with another tenant's workspace id succeeded",
    before: "updateWorkspaceCollab(ctxB, idA) mutated A",
    after: "Cross-tenant update is not-found and row unchanged",
    evidenceTest: "p1-isolation.test.ts:cross-tenant update is not-found",
  },
  {
    id: "P1.1-cross-tenant-delete",
    p1: "P1.1",
    bug: "deleteWorkspace from another tenant removed the row",
    before: "deleteWorkspace(ctxB, idA) deleted A",
    after: "Cross-tenant delete is not-found; row remains",
    evidenceTest: "p1-isolation.test.ts:cross-tenant delete is not-found",
  },
  {
    id: "P1.1-cross-tenant-fk-member",
    p1: "P1.1",
    bug: "Workspace created_by pointed at a member of another tenant",
    before: "INSERT succeeded across tenants",
    after: "Composite FK rejects cross-tenant created_by",
    evidenceTest: "p1-isolation.test.ts:cross-tenant member FK is rejected",
  },
  {
    id: "P1.1-cross-tenant-fk-workspace",
    p1: "P1.1",
    bug: "Collab row referenced another tenant's workspace id",
    before: "INSERT into collab with mixed tenant/workspace succeeded",
    after: "Composite FK rejects cross-tenant workspace pointer",
    evidenceTest: "p1-isolation.test.ts:cross-tenant workspace FK is rejected",
  },
  {
    id: "P1.1-same-user-two-tenants",
    p1: "P1.1",
    bug: "user_key uniqueness was global so isolation collapsed",
    before: "One membership row for alice across orgs",
    after: "Same user_key in two tenants cannot list the other tenant",
    evidenceTest: "p1-isolation.test.ts:same user_key in two tenants is isolated",
  },
  {
    id: "P1.1-fail-closed-leak",
    p1: "P1.1",
    bug: "Other-tenant id returned 403 with a distinct message",
    before: "Existence leak via error class/message",
    after: "Missing and other-tenant share not-found",
    evidenceTest: "p1-isolation.test.ts:missing and other-tenant are indistinguishable",
  },
  {
    id: "P1.1-bootstrap-not-public",
    p1: "P1.1",
    bug: "Anyone could insert tenant+owner",
    before: "bootstrapTenant({}) created an owner",
    after: "Unlock with configured secret required; empty secret disables",
    evidenceTest: "p1-isolation.test.ts:bootstrap without unlock is denied",
  },
  {
    id: "P1.1-persist-allowlist",
    p1: "P1.1",
    bug: "Raw HAR/JWT/cookie persisted on collab write",
    before: "aRaw and compact JWT stored in report_dto_json",
    after: "assertAllowedCollab rejects capture secrets",
    evidenceTest: "p1-isolation.test.ts:collab write rejects raw capture secrets",
  },
  {
    id: "P1.1-persist-redacted-dto",
    p1: "P1.1",
    bug: "Guard rejected a genuine deep-redacted ReportDTO (replays.raw / Bearer [redacted])",
    before: "toReportDTO(analyze(demo)) could not be stored",
    after: "Engine ReportDTO persists; compact JWT and live Bearer still rejected",
    evidenceTest: "p1-isolation.test.ts:deep-redacted ReportDTO from the solo engine is persistable",
  },
  {
    id: "P1.1-migration-atomic",
    p1: "P1.1",
    bug: "Failed 0003 left team_tenant without members table",
    before: "Half-applied kernel schema",
    after: "Failed transaction rolls back all Team DDL",
    evidenceTest: "p1-isolation.test.ts:failed team migration leaves no half-applied tables",
  },
  {
    id: "P1.1-solo-lab-untouched",
    p1: "P1.1",
    bug: "Team kernel imported platform auth or broke lab/solo",
    before: "Auth-on coupling; lab login failed",
    after: "No authMiddleware import; demo BOLA and lab login still work",
    evidenceTest: "p1-solo-lab.test.ts:team sources do not import platform auth",
  },
  {
    id: "P1.1-no-auth-schema-copy",
    p1: "P1.1",
    bug: "0001_auth.sql copied into migrations glob",
    before: "Auth-off product applied Better Auth schema",
    after: "0001_auth.sql stays under migrations/auth/",
    evidenceTest: "p1-solo-lab.test.ts:auth schema stays out of the product glob",
  },
];

export function gatesFor(p1: P1Item): P1Gate[] {
  return P1_GATES.filter((g) => g.p1 === p1);
}
