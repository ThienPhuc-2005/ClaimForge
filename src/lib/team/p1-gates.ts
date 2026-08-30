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
    id: "P1.1-no-public-context-factory",
    p1: "P1.1",
    bug: "contextFromMember(arbitrary member) minted a branded TenantContext",
    before: "Public factory stamped any {tenantId,userKey,role}",
    after: "Only bootstrap/resolve after a DB membership row; member objects are not context",
    evidenceTest: "p1-isolation.test.ts:no public factory turns a member object into TenantContext",
  },
  {
    id: "P1.1-caller-tenant-id",
    p1: "P1.1",
    bug: "tenant_id taken from body/input",
    before: "createWorkspace({ tenantId: victim }) wrote into victim",
    after: "Caller tenantId is rejected; SQL uses bound identity from WeakMap",
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
    id: "P1.1-persist-strict-schema",
    p1: "P1.1",
    bug: "Heuristic walk allowed api_key, sessionSecret, unknown nested fields, HTTP dumps",
    before: "Forbidden keys missed underscore variants; extra fields stored",
    after: "Strict ReportDTO/policy schema; unknown fields, HTTP smuggling, oversize Base64 rejected",
    evidenceTest: "p1-isolation.test.ts:collab persist rejects smuggled secrets and unknown fields",
  },
  {
    id: "P1.1-persist-redacted-dto",
    p1: "P1.1",
    bug: "Guard rejected a genuine deep-redacted ReportDTO (replays.raw / Bearer [redacted])",
    before: "toReportDTO(analyze(demo)) could not be stored",
    after: "Engine ReportDTO is re-redacted into a new object and persisted",
    evidenceTest: "p1-isolation.test.ts:deep-redacted ReportDTO from the solo engine is persistable",
  },
  {
    id: "P1.1-persist-read-sanitize",
    p1: "P1.1",
    bug: "Tampered report_dto_json returned to the caller",
    before: "getCollab trusted stored JSON",
    after: "Read path re-validates schema and redaction; tamper is PersistError",
    evidenceTest: "p1-isolation.test.ts:tampered collab row is rejected on read",
  },
  {
    id: "P1.1-collab-upsert-atomic",
    p1: "P1.1",
    bug: "Two first-writes raced to INSERT and one 23505'd or clobbered the other column",
    before: "SELECT then INSERT/UPDATE",
    after: "INSERT ON CONFLICT DO UPDATE merges columns; one row",
    evidenceTest: "p1-isolation.test.ts:concurrent first collab writes upsert to one row",
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
  {
    id: "P1.1-context-frozen-identity",
    p1: "P1.1",
    bug: "Branded TenantContext fields were writable so tenantId could be retargeted",
    before: "alice.context.tenantId = bob listed bob's workspaces",
    after: "Context is frozen; WeakMap identity is the SQL authority",
    evidenceTest: "p1-isolation.test.ts:mutated tenantId on a branded context cannot access another tenant",
  },
  {
    id: "P1.1-symbol-copy-rejected",
    p1: "P1.1",
    bug: "Object.getOwnPropertySymbols copied the brand onto a forged context",
    before: "Copied symbol + victim tenantId passed assertTenantContext",
    after: "Unknown object is missing from WeakMap and is TeamIsolationError",
    evidenceTest: "p1-isolation.test.ts:symbol copied onto a new object is rejected",
  },
  {
    id: "P1.1-revoked-member-context",
    p1: "P1.1",
    bug: "Deleted membership left a minted context usable",
    before: "carol context still listed workspaces after DELETE team_member",
    after: "requireActiveMember re-SELECTs membership and fail-closes",
    evidenceTest: "p1-isolation.test.ts:revoked member context cannot be reused",
  },
  {
    id: "P1.1-bootstrap-actor-registry",
    p1: "P1.1",
    bug: "Copied bootstrap brand unlocked tenant creation",
    before: "Fake {brand, label: operator} called bootstrapTenant",
    after: "BootstrapActor must be in WeakMap; copies are TeamBootstrapError",
    evidenceTest: "p1-isolation.test.ts:copied BootstrapActor cannot unlock tenant creation",
  },
  {
    id: "P1.1-persist-team-projection",
    p1: "P1.1",
    bug: "loot.value and replays.raw/curl stored caller strings",
    before: "curl -u and loot secrets survived re-redact heuristics",
    after: "Team projection always stores [redacted] for loot.value and replay blobs",
    evidenceTest: "p1-isolation.test.ts:team projection strips loot and replay credentials from stored JSON",
  },
  {
    id: "P1.1-persist-credential-canaries",
    p1: "P1.1",
    bug: "curl -u, Basic, Cookie, AWS keys in remaining strings were stored",
    before: "Canary scan missed curl user and AWS access keys",
    after: "Defense-in-depth canaries reject live credentials outside projection holes",
    evidenceTest: "p1-isolation.test.ts:live credential canaries still reject secrets outside the projection holes",
  },
];

export function gatesFor(p1: P1Item): P1Gate[] {
  return P1_GATES.filter((g) => g.p1 === p1);
}
