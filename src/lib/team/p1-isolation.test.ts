import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { PGlite } from "@electric-sql/pglite";
import { DEFAULT_POLICY } from "../claimforge/policy.ts";
import { analyze } from "../claimforge/analyze.ts";
import { demoActorA, demoActorB } from "../claimforge/demo.ts";
import { toReportDTO } from "../claimforge/report-dto.ts";
import * as contextApi from "./context.ts";
import { unlockBootstrap, type TenantContext } from "./context.ts";
import { TeamBootstrapError, TeamIsolationError, TeamNotFoundError, TeamPersistError } from "./errors.ts";
import { TEAM_LIMITS } from "./persist-guard.ts";
import * as repoApi from "./repo.ts";
import {
  addMember,
  bootstrapTenant,
  createWorkspace,
  deleteWorkspace,
  getCollab,
  getTenant,
  getWorkspace,
  listMembers,
  listWorkspaces,
  resolveTenantContext,
  updateWorkspaceCollab,
} from "./repo.ts";
import type { TeamSql } from "./types.ts";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "../../..");
const SECRET = "test-bootstrap-secret-1";
const LAB_SQL = readFileSync(join(root, "migrations/0002_lab_revoke.sql"), "utf8");
const TEAM_SQL = readFileSync(join(root, "migrations/0003_team_isolation.sql"), "utf8");
const AUDIT_SQL = readFileSync(join(root, "migrations/0005_team_audit.sql"), "utf8");

function wrapSql(client: {
  query: (text: string, params?: unknown[]) => Promise<{ rows: unknown[] }>;
  transaction?: <T>(fn: (tx: never) => Promise<T>) => Promise<T>;
}): TeamSql {
  const sql: TeamSql = {
    query: async <T = Record<string, unknown>>(text: string, params: unknown[] = []) => {
      const result = await client.query(text, params);
      return result.rows as T[];
    },
    transaction: (fn) => {
      if (typeof client.transaction !== "function") return fn(sql);
      return client.transaction((tx) => fn(wrapSql(tx as never)));
    },
  };
  return sql;
}

async function openKernel() {
  const pg = new PGlite();
  await pg.waitReady;
  await pg.exec(LAB_SQL);
  await pg.exec(TEAM_SQL);
  await pg.exec(AUDIT_SQL);
  return { pg, sql: wrapSql(pg as never) };
}

function operator() {
  return unlockBootstrap(SECRET, SECRET);
}

const DTO = {
  schemaVersion: "report-dto-1",
  tool: "ClaimForge",
  secrets: "redacted",
  generated: "2026-08-30T00:00:00.000Z",
  engineVersion: "0.9.0-p0.7",
  ruleVersion: "bola-trust-1",
  policyVersion: "policy-1",
  inputHash: "in",
  resultHash: "out",
  actors: { A: "alice", B: "bob" },
  findings: [],
  diffs: [],
  timeline: [],
  jwts: [],
  cookies: [],
  graph: { nodes: [], edges: [] },
  loot: [],
  wordlists: { ids: [], emails: [], roles: [], hosts: [] },
  paths: [],
  replays: [],
  surface: [],
  redaction: { dropped: [], preview: [] },
};

const FINDING = {
  id: "F1",
  severity: "low" as const,
  confidence: "observation" as const,
  reviewState: "new" as const,
  title: "note",
  why: "why",
  how: "how",
  evidence: [],
  cwe: [],
  owasp: [],
  cvssDraft: { score: null, vector: null, status: "draft" as const },
  preconditions: [],
  reproduce: [],
  expected: "deny",
  actual: "allow",
  impact: "info",
  remediation: "fix",
  retest: null,
  reasonCodes: [],
  missingEvidence: [],
};

const HTTP_DUMP = "GET /secret HTTP/1.1\r\nHost: lab.test\r\nAuthorization: Bearer abc\r\n\r\n";

test("bootstrap without unlock is denied", async () => {
  const { sql } = await openKernel();
  await assert.rejects(
    () =>
      bootstrapTenant(sql, { label: "operator" } as never, {
        slug: "acme",
        name: "Acme",
        ownerUserKey: "alice",
      }),
    TeamBootstrapError,
  );
  await assert.throws(() => unlockBootstrap(SECRET, ""), TeamBootstrapError);
  await assert.throws(() => unlockBootstrap("wrong-bootstrap-secret-1", SECRET), TeamBootstrapError);
});

test("forged TenantContext without brand is rejected", async () => {
  const { sql } = await openKernel();
  const a = await bootstrapTenant(sql, operator(), { slug: "acme", name: "Acme", ownerUserKey: "alice" });
  const ws = await createWorkspace(sql, a.context, { name: "desk" });
  const forged = { tenantId: a.tenant.id, userKey: "alice", role: "owner" } as TenantContext;
  await assert.rejects(() => getWorkspace(sql, forged, ws.id), TeamIsolationError);
  await assert.rejects(() => listWorkspaces(sql, forged), TeamIsolationError);
});

test("no public factory turns a member object into TenantContext", async () => {
  assert.equal("contextFromMember" in contextApi, false);
  assert.equal("contextFromMember" in repoApi, false);
  const files = readdirSync(here).filter((f) => f.endsWith(".ts") && !f.endsWith(".test.ts"));
  for (const file of files) {
    const src = readFileSync(join(here, file), "utf8");
    assert.equal(/\bexport\s+(async\s+)?function\s+contextFromMember\b/.test(src), false, file);
    assert.equal(/\bexport\s+const\s+contextFromMember\b/.test(src), false, file);
    assert.equal(/\bexport\s+default\b[^;]*\bcontextFromMember\b/.test(src), false, file);
    assert.equal(/\bexport\s*\{[^}]*\bcontextFromMember\b/.test(src), false, file);
    assert.equal(/\bexport\s+(async\s+)?function\s+tenantContextFromDbRow\b/.test(src), false, file);
    assert.equal(/\bexport\s+const\s+tenantContextFromDbRow\b/.test(src), false, file);
    assert.equal(/\bexport\s*\{[^}]*\btenantContextFromDbRow\b/.test(src), false, file);
  }
  const { sql } = await openKernel();
  const a = await bootstrapTenant(sql, operator(), { slug: "acme", name: "Acme", ownerUserKey: "alice" });
  await assert.rejects(() => getWorkspace(sql, a.owner as never, randomUUID()), TeamIsolationError);
  const fake = { tenantId: a.tenant.id, userKey: "alice", role: "owner", createdAt: a.owner.createdAt };
  await assert.rejects(() => listWorkspaces(sql, fake as never), TeamIsolationError);
});

test("caller-supplied tenantId on input is rejected", async () => {
  const { sql } = await openKernel();
  const a = await bootstrapTenant(sql, operator(), { slug: "acme", name: "Acme", ownerUserKey: "alice" });
  const b = await bootstrapTenant(sql, operator(), { slug: "beta", name: "Beta", ownerUserKey: "bob" });
  await assert.rejects(
    () => createWorkspace(sql, a.context, { name: "desk", tenantId: b.tenant.id } as never),
    TeamIsolationError,
  );
  await assert.rejects(
    () => addMember(sql, a.context, { userKey: "carol", role: "viewer", tenant_id: b.tenant.id } as never),
    TeamIsolationError,
  );
  const ws = await createWorkspace(sql, a.context, { name: "desk" });
  assert.equal(ws.tenantId, a.tenant.id);
  assert.equal((await listWorkspaces(sql, b.context)).length, 0);
});

test("cross-tenant read is not-found", async () => {
  const { sql } = await openKernel();
  const a = await bootstrapTenant(sql, operator(), { slug: "acme", name: "Acme", ownerUserKey: "alice" });
  const b = await bootstrapTenant(sql, operator(), { slug: "beta", name: "Beta", ownerUserKey: "bob" });
  const ws = await createWorkspace(sql, a.context, { name: "desk" });
  await assert.rejects(() => getWorkspace(sql, b.context, ws.id), TeamNotFoundError);
  assert.equal((await listWorkspaces(sql, a.context)).length, 1);
});

test("cross-tenant update is not-found", async () => {
  const { sql } = await openKernel();
  const a = await bootstrapTenant(sql, operator(), { slug: "acme", name: "Acme", ownerUserKey: "alice" });
  const b = await bootstrapTenant(sql, operator(), { slug: "beta", name: "Beta", ownerUserKey: "bob" });
  const ws = await createWorkspace(sql, a.context, { name: "desk" });
  await updateWorkspaceCollab(sql, a.context, ws.id, { policy: DEFAULT_POLICY });
  await assert.rejects(
    () => updateWorkspaceCollab(sql, b.context, ws.id, { review: { f1: "confirmed" } }),
    TeamNotFoundError,
  );
  const collab = await getCollab(sql, a.context, ws.id);
  assert.equal(collab?.review, null);
  assert.ok(collab?.policy);
});

test("cross-tenant delete is not-found", async () => {
  const { sql } = await openKernel();
  const a = await bootstrapTenant(sql, operator(), { slug: "acme", name: "Acme", ownerUserKey: "alice" });
  const b = await bootstrapTenant(sql, operator(), { slug: "beta", name: "Beta", ownerUserKey: "bob" });
  const ws = await createWorkspace(sql, a.context, { name: "desk" });
  await assert.rejects(() => deleteWorkspace(sql, b.context, ws.id), TeamNotFoundError);
  assert.equal((await getWorkspace(sql, a.context, ws.id)).id, ws.id);
});

test("cross-tenant member FK is rejected", async () => {
  const { sql } = await openKernel();
  const a = await bootstrapTenant(sql, operator(), { slug: "acme", name: "Acme", ownerUserKey: "alice" });
  const b = await bootstrapTenant(sql, operator(), { slug: "beta", name: "Beta", ownerUserKey: "bob" });
  await assert.rejects(() =>
    sql.query(
      "INSERT INTO team_workspace (tenant_id, id, name, created_by_user_key) VALUES ($1, $2, $3, $4)",
      [a.tenant.id, randomUUID(), "stolen", b.owner.userKey],
    ),
  );
  assert.equal((await listWorkspaces(sql, a.context)).length, 0);
});

test("cross-tenant workspace FK is rejected", async () => {
  const { sql } = await openKernel();
  const a = await bootstrapTenant(sql, operator(), { slug: "acme", name: "Acme", ownerUserKey: "alice" });
  const b = await bootstrapTenant(sql, operator(), { slug: "beta", name: "Beta", ownerUserKey: "bob" });
  const wsB = await createWorkspace(sql, b.context, { name: "beta-desk" });
  await assert.rejects(() =>
    sql.query(
      "INSERT INTO team_workspace_collab (tenant_id, workspace_id, updated_by_user_key) VALUES ($1, $2, $3)",
      [a.tenant.id, wsB.id, a.owner.userKey],
    ),
  );
});

test("same user_key in two tenants is isolated", async () => {
  const { sql } = await openKernel();
  const a = await bootstrapTenant(sql, operator(), { slug: "acme", name: "Acme", ownerUserKey: "alice" });
  const b = await bootstrapTenant(sql, operator(), { slug: "beta", name: "Beta", ownerUserKey: "alice" });
  const wsA = await createWorkspace(sql, a.context, { name: "a-desk" });
  const wsB = await createWorkspace(sql, b.context, { name: "b-desk" });
  const ctxA = await resolveTenantContext(sql, "alice", a.tenant.id);
  const ctxB = await resolveTenantContext(sql, "alice", b.tenant.id);
  assert.equal(ctxA.tenantId, a.tenant.id);
  assert.equal(ctxB.tenantId, b.tenant.id);
  assert.deepEqual(
    (await listWorkspaces(sql, ctxA)).map((w) => w.id),
    [wsA.id],
  );
  assert.deepEqual(
    (await listWorkspaces(sql, ctxB)).map((w) => w.id),
    [wsB.id],
  );
  await assert.rejects(() => getWorkspace(sql, ctxA, wsB.id), TeamNotFoundError);
});

test("missing and other-tenant are indistinguishable", async () => {
  const { sql } = await openKernel();
  const a = await bootstrapTenant(sql, operator(), { slug: "acme", name: "Acme", ownerUserKey: "alice" });
  const b = await bootstrapTenant(sql, operator(), { slug: "beta", name: "Beta", ownerUserKey: "bob" });
  const ws = await createWorkspace(sql, a.context, { name: "desk" });
  const missing = randomUUID();
  const errOther = await getWorkspace(sql, b.context, ws.id).then(
    () => null,
    (e: unknown) => e,
  );
  const errMissing = await getWorkspace(sql, b.context, missing).then(
    () => null,
    (e: unknown) => e,
  );
  assert.ok(errOther instanceof TeamNotFoundError);
  assert.ok(errMissing instanceof TeamNotFoundError);
  assert.equal((errOther as TeamNotFoundError).message, (errMissing as TeamNotFoundError).message);
  assert.equal((errOther as TeamNotFoundError).code, "not_found");
  assert.ok(!String((errOther as Error).message).includes(a.tenant.id));
});

test("collab write rejects raw capture secrets", async () => {
  const { sql } = await openKernel();
  const a = await bootstrapTenant(sql, operator(), { slug: "acme", name: "Acme", ownerUserKey: "alice" });
  const ws = await createWorkspace(sql, a.context, { name: "desk" });
  const jwt = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJhIn0.";
  await assert.rejects(
    () => updateWorkspaceCollab(sql, a.context, ws.id, { reportDto: { ...DTO, aRaw: "GET /" } as never }),
    TeamPersistError,
  );
  await assert.rejects(() =>
    updateWorkspaceCollab(sql, a.context, ws.id, {
      reportDto: { ...DTO, findings: [{ title: `Bearer ${jwt}` }] },
    }),
  );
  const ok = await updateWorkspaceCollab(sql, a.context, ws.id, {
    policy: DEFAULT_POLICY,
    review: { f1: "needs-evidence" },
    reportDto: DTO,
  });
  assert.equal(ok.policy?.version, DEFAULT_POLICY.version);
  assert.equal(ok.review?.f1, "needs-evidence");
  assert.equal((ok.reportDto as { secrets: string }).secrets, "redacted");
});

test("collab persist rejects smuggled secrets and unknown fields", async () => {
  const { sql } = await openKernel();
  const a = await bootstrapTenant(sql, operator(), { slug: "acme", name: "Acme", ownerUserKey: "alice" });
  const ws = await createWorkspace(sql, a.context, { name: "desk" });
  await assert.rejects(
    () => updateWorkspaceCollab(sql, a.context, ws.id, { reportDto: { ...DTO, api_key: "sk-live" } as never }),
    TeamPersistError,
  );
  await assert.rejects(
    () =>
      updateWorkspaceCollab(sql, a.context, ws.id, {
        reportDto: { ...DTO, sessionSecret: "sess" } as never,
      }),
    TeamPersistError,
  );
  await assert.rejects(
    () =>
      updateWorkspaceCollab(sql, a.context, ws.id, {
        reportDto: { ...DTO, comment: HTTP_DUMP } as never,
      }),
    TeamPersistError,
  );
  await assert.rejects(
    () =>
      updateWorkspaceCollab(sql, a.context, ws.id, {
        reportDto: { ...DTO, findings: [{ ...FINDING, extra: "nope" }] },
      }),
    TeamPersistError,
  );
  await assert.rejects(
    () =>
      updateWorkspaceCollab(sql, a.context, ws.id, {
        reportDto: { ...DTO, findings: [{ ...FINDING, why: HTTP_DUMP }] },
      }),
    TeamPersistError,
  );
  await assert.rejects(
    () =>
      updateWorkspaceCollab(sql, a.context, ws.id, {
        reportDto: { ...DTO, findings: [{ ...FINDING, title: "A".repeat(TEAM_LIMITS.base64Run) }] },
      }),
    TeamPersistError,
  );
  await assert.rejects(
    () =>
      updateWorkspaceCollab(sql, a.context, ws.id, {
        review: { api_key: "confirmed" },
      }),
    TeamPersistError,
  );
  await assert.rejects(
    () =>
      updateWorkspaceCollab(sql, a.context, ws.id, {
        policy: { ...DEFAULT_POLICY, sessionSecret: "x" } as never,
      }),
    TeamPersistError,
  );
  await assert.rejects(
    () =>
      updateWorkspaceCollab(sql, a.context, ws.id, {
        reportDto: { ...DTO, findings: [{ ...FINDING, title: "x".repeat(TEAM_LIMITS.stringChars + 1) }] },
      }),
    TeamPersistError,
  );
});

test("deep-redacted ReportDTO from the solo engine is persistable", async () => {
  const { sql } = await openKernel();
  const a = await bootstrapTenant(sql, operator(), { slug: "acme", name: "Acme", ownerUserKey: "alice" });
  const ws = await createWorkspace(sql, a.context, { name: "desk" });
  const dto = toReportDTO(analyze(demoActorA(), demoActorB(), "alice", "bob"));
  const saved = await updateWorkspaceCollab(sql, a.context, ws.id, { reportDto: dto });
  assert.notEqual(saved.reportDto, dto);
  assert.equal((saved.reportDto as { secrets: string }).secrets, "redacted");
  const replays = (saved.reportDto as { replays: { raw: string; curl: string }[] }).replays;
  assert.ok(Array.isArray(replays));
  for (const replay of replays) {
    assert.equal(replay.raw, "[redacted]");
    assert.equal(replay.curl, "[redacted]");
  }
  const loot = (saved.reportDto as { loot: { value: string }[] }).loot;
  for (const item of loot) assert.equal(item.value, "[redacted]");
});

test("tampered collab row is rejected on read", async () => {
  const { sql } = await openKernel();
  const a = await bootstrapTenant(sql, operator(), { slug: "acme", name: "Acme", ownerUserKey: "alice" });
  const ws = await createWorkspace(sql, a.context, { name: "desk" });
  await updateWorkspaceCollab(sql, a.context, ws.id, { reportDto: DTO });
  await sql.query(
    "UPDATE team_workspace_collab SET report_dto_json = $3 WHERE tenant_id = $1 AND workspace_id = $2",
    [a.tenant.id, ws.id, JSON.stringify({ ...DTO, api_key: "sk-live", aRaw: HTTP_DUMP })],
  );
  await assert.rejects(() => getCollab(sql, a.context, ws.id), TeamPersistError);
});

test("concurrent first collab writes upsert to one row", async () => {
  const { sql } = await openKernel();
  const a = await bootstrapTenant(sql, operator(), { slug: "acme", name: "Acme", ownerUserKey: "alice" });
  const ws = await createWorkspace(sql, a.context, { name: "desk" });
  await Promise.all([
    updateWorkspaceCollab(sql, a.context, ws.id, { policy: DEFAULT_POLICY }),
    updateWorkspaceCollab(sql, a.context, ws.id, { review: { f1: "confirmed" } }),
  ]);
  const collab = await getCollab(sql, a.context, ws.id);
  assert.ok(collab);
  assert.equal(collab.policy?.version, DEFAULT_POLICY.version);
  assert.equal(collab.review?.f1, "confirmed");
  const count = await sql.query<{ n: string | number }>(
    "SELECT COUNT(*)::text AS n FROM team_workspace_collab WHERE tenant_id = $1 AND workspace_id = $2",
    [a.tenant.id, ws.id],
  );
  assert.equal(String(count[0]?.n), "1");
});

test("failed team migration leaves no half-applied tables", async () => {
  const pg = new PGlite();
  await pg.waitReady;
  await pg.exec(LAB_SQL);
  try {
    await pg.transaction(async (tx) => {
      await tx.exec(TEAM_SQL);
      await tx.exec("CREATE TABLE team_orphan_should_not_exist (id text)");
      throw new Error("injected failure");
    });
  } catch (err) {
    assert.equal((err as Error).message, "injected failure");
  }
  const team = await pg.query<{ rel: string | null }>("SELECT to_regclass('public.team_tenant') AS rel");
  const member = await pg.query<{ rel: string | null }>("SELECT to_regclass('public.team_member') AS rel");
  const orphan = await pg.query<{ rel: string | null }>(
    "SELECT to_regclass('public.team_orphan_should_not_exist') AS rel",
  );
  const lab = await pg.query<{ rel: string | null }>("SELECT to_regclass('public.lab_revoke') AS rel");
  assert.equal(team.rows[0]?.rel, null);
  assert.equal(member.rows[0]?.rel, null);
  assert.equal(orphan.rows[0]?.rel, null);
  assert.ok(lab.rows[0]?.rel);
});

test("resolve ignores unlinked requested tenant and does not leak", async () => {
  const { sql } = await openKernel();
  await bootstrapTenant(sql, operator(), { slug: "acme", name: "Acme", ownerUserKey: "alice" });
  const b = await bootstrapTenant(sql, operator(), { slug: "beta", name: "Beta", ownerUserKey: "bob" });
  await assert.rejects(() => resolveTenantContext(sql, "alice", b.tenant.id), TeamNotFoundError);
  await assert.rejects(() => resolveTenantContext(sql, "alice", randomUUID()), TeamNotFoundError);
});

test("addMember stays inside verified tenant", async () => {
  const { sql } = await openKernel();
  const a = await bootstrapTenant(sql, operator(), { slug: "acme", name: "Acme", ownerUserKey: "alice" });
  const b = await bootstrapTenant(sql, operator(), { slug: "beta", name: "Beta", ownerUserKey: "bob" });
  await addMember(sql, a.context, { userKey: "carol", role: "analyst" });
  const members = await listMembers(sql, a.context);
  assert.ok(members.some((m) => m.userKey === "carol"));
  assert.equal((await listMembers(sql, b.context)).some((m) => m.userKey === "carol"), false);
});

test("mutated tenantId on a branded context cannot access another tenant", async () => {
  const { sql } = await openKernel();
  const a = await bootstrapTenant(sql, operator(), { slug: "acme", name: "Acme", ownerUserKey: "alice" });
  const b = await bootstrapTenant(sql, operator(), { slug: "beta", name: "Beta", ownerUserKey: "bob" });
  const wsB = await createWorkspace(sql, b.context, { name: "beta-desk" });
  await updateWorkspaceCollab(sql, b.context, wsB.id, { policy: DEFAULT_POLICY });
  assert.equal(Object.isFrozen(a.context), true);
  assert.throws(() => {
    (a.context as { tenantId: string }).tenantId = b.tenant.id;
  }, TypeError);
  assert.throws(() => {
    (a.context as { userKey: string }).userKey = "bob";
  }, TypeError);
  assert.throws(() => {
    (a.context as { role: string }).role = "viewer";
  }, TypeError);
  assert.equal(a.context.tenantId, a.tenant.id);
  assert.deepEqual(await listWorkspaces(sql, a.context), []);
  await assert.rejects(() => getWorkspace(sql, a.context, wsB.id), TeamNotFoundError);
  await assert.rejects(() => getCollab(sql, a.context, wsB.id), TeamNotFoundError);
  await assert.rejects(() => deleteWorkspace(sql, a.context, wsB.id), TeamNotFoundError);
  await addMember(sql, a.context, { userKey: "mallory", role: "viewer" });
  assert.equal((await listMembers(sql, b.context)).some((m) => m.userKey === "mallory"), false);
  assert.equal((await listMembers(sql, a.context)).some((m) => m.userKey === "mallory"), true);
  assert.equal((await getWorkspace(sql, b.context, wsB.id)).id, wsB.id);
  assert.ok((await getCollab(sql, b.context, wsB.id))?.policy);
});

test("symbol copied onto a new object is rejected", async () => {
  const { sql } = await openKernel();
  const a = await bootstrapTenant(sql, operator(), { slug: "acme", name: "Acme", ownerUserKey: "alice" });
  const b = await bootstrapTenant(sql, operator(), { slug: "beta", name: "Beta", ownerUserKey: "bob" });
  const wsB = await createWorkspace(sql, b.context, { name: "beta-desk" });
  const brand = Object.getOwnPropertySymbols(a.context)[0]!;
  const forged = { [brand]: true, tenantId: b.tenant.id, userKey: "bob", role: "owner" } as TenantContext;
  await assert.rejects(() => listWorkspaces(sql, forged), TeamIsolationError);
  await assert.rejects(() => getWorkspace(sql, forged, wsB.id), TeamIsolationError);
  await assert.rejects(() => getCollab(sql, forged, wsB.id), TeamIsolationError);
  await assert.rejects(() => listMembers(sql, forged), TeamIsolationError);
  await assert.rejects(() => addMember(sql, forged, { userKey: "mallory", role: "owner" }), TeamIsolationError);
  await assert.rejects(() => deleteWorkspace(sql, forged, wsB.id), TeamIsolationError);
  await assert.rejects(() => getTenant(sql, forged), TeamIsolationError);
  assert.equal((await getWorkspace(sql, b.context, wsB.id)).id, wsB.id);
  assert.equal((await listMembers(sql, b.context)).some((m) => m.userKey === "mallory"), false);
});

test("revoked member context cannot be reused", async () => {
  const { sql } = await openKernel();
  const a = await bootstrapTenant(sql, operator(), { slug: "acme", name: "Acme", ownerUserKey: "alice" });
  await createWorkspace(sql, a.context, { name: "desk" });
  await addMember(sql, a.context, { userKey: "carol", role: "analyst" });
  const carol = await resolveTenantContext(sql, "carol", a.tenant.id);
  const before = (await listWorkspaces(sql, carol)).length;
  assert.equal(before, 1);
  await sql.query("DELETE FROM team_member WHERE tenant_id = $1 AND user_key = $2", [a.tenant.id, "carol"]);
  await assert.rejects(() => listWorkspaces(sql, carol), TeamNotFoundError);
  await assert.rejects(() => getTenant(sql, carol), TeamNotFoundError);
  await assert.rejects(() => addMember(sql, carol, { userKey: "dave", role: "viewer" }), TeamNotFoundError);
  assert.equal((await listWorkspaces(sql, a.context)).length, 1);
  assert.equal((await listMembers(sql, a.context)).some((m) => m.userKey === "carol"), false);
  assert.equal((await listMembers(sql, a.context)).some((m) => m.userKey === "dave"), false);
});

test("copied BootstrapActor cannot unlock tenant creation", async () => {
  const { sql } = await openKernel();
  const actor = operator();
  assert.equal(Object.isFrozen(actor), true);
  const brand = Object.getOwnPropertySymbols(actor)[0]!;
  const fake = { [brand]: true, label: "operator" };
  await assert.rejects(
    () => bootstrapTenant(sql, fake as never, { slug: "gamma", name: "Gamma", ownerUserKey: "eve" }),
    TeamBootstrapError,
  );
  assert.throws(() => {
    (actor as { label: string }).label = "attacker";
  }, TypeError);
});

test("team projection strips loot and replay credentials from stored JSON", async () => {
  const { sql } = await openKernel();
  const a = await bootstrapTenant(sql, operator(), { slug: "acme", name: "Acme", ownerUserKey: "alice" });
  const ws = await createWorkspace(sql, a.context, { name: "desk" });
  const secret = "supersecretpassword";
  const aws = "AKIAIOSFODNN7EXAMPLE";
  const saved = await updateWorkspaceCollab(sql, a.context, ws.id, {
    reportDto: {
      ...DTO,
      loot: [
        { kind: "note", severity: "low", label: "pw", value: secret, where: "body", actor: "A" },
        { kind: "key", severity: "high", label: "aws", value: aws, where: "env", actor: "B" },
      ],
      replays: [
        {
          id: "r1",
          title: "login",
          severity: "low",
          note: "n",
          curl: "curl -u alice:supersecret http://lab.test/me",
          raw: "GET /me HTTP/1.1\r\nHost: lab.test\r\nAuthorization: Basic dXNlcjpwYXNz\r\nCookie: session=live-secret\r\n\r\n",
        },
        {
          id: "r2",
          title: "user",
          severity: "low",
          note: "n",
          curl: "curl --user bob:hunter2 http://lab.test/me",
          raw: "GET / HTTP/1.1\r\nHost: x\r\n\r\n",
        },
      ],
    },
  });
  const json = JSON.stringify(saved.reportDto);
  assert.equal(json.includes(secret), false);
  assert.equal(json.includes(aws), false);
  assert.equal(json.includes("supersecret"), false);
  assert.equal(json.includes("hunter2"), false);
  assert.equal(json.includes("live-secret"), false);
  assert.equal(json.includes("dXNlcjpwYXNz"), false);
  assert.equal(json.includes("curl -u"), false);
  const stored = await sql.query<{ report_dto_json: string }>(
    "SELECT report_dto_json FROM team_workspace_collab WHERE tenant_id = $1 AND workspace_id = $2",
    [a.tenant.id, ws.id],
  );
  const rawJson = stored[0]?.report_dto_json ?? "";
  assert.equal(rawJson.includes(secret), false);
  assert.equal(rawJson.includes(aws), false);
  assert.equal(rawJson.includes("hunter2"), false);
  assert.equal(rawJson.includes("live-secret"), false);
  const loot = (saved.reportDto as { loot: { value: string }[] }).loot;
  assert.ok(loot.length >= 2);
  for (const item of loot) assert.equal(item.value, "[redacted]");
  const replays = (saved.reportDto as { replays: { raw: string; curl: string }[] }).replays;
  for (const replay of replays) {
    assert.equal(replay.raw, "[redacted]");
    assert.equal(replay.curl, "[redacted]");
  }
});

test("live credential canaries still reject secrets outside the projection holes", async () => {
  const { sql } = await openKernel();
  const a = await bootstrapTenant(sql, operator(), { slug: "acme", name: "Acme", ownerUserKey: "alice" });
  const ws = await createWorkspace(sql, a.context, { name: "desk" });
  await assert.rejects(
    () =>
      updateWorkspaceCollab(sql, a.context, ws.id, {
        reportDto: { ...DTO, findings: [{ ...FINDING, why: "curl -u alice:supersecret http://x" }] },
      }),
    TeamPersistError,
  );
  await assert.rejects(
    () =>
      updateWorkspaceCollab(sql, a.context, ws.id, {
        reportDto: { ...DTO, findings: [{ ...FINDING, title: "AKIAIOSFODNN7EXAMPLE" }] },
      }),
    TeamPersistError,
  );
  await assert.rejects(
    () =>
      updateWorkspaceCollab(sql, a.context, ws.id, {
        reportDto: { ...DTO, findings: [{ ...FINDING, how: "Authorization: Basic dXNlcjpwYXNz" }] },
      }),
    TeamPersistError,
  );
  await assert.rejects(
    () =>
      updateWorkspaceCollab(sql, a.context, ws.id, {
        reportDto: { ...DTO, findings: [{ ...FINDING, evidence: ["Cookie: session=live-secret"] }] },
      }),
    TeamPersistError,
  );
  await assert.rejects(
    () =>
      updateWorkspaceCollab(sql, a.context, ws.id, {
        reportDto: { ...DTO, findings: [{ ...FINDING, why: "curl --user bob:hunter2 http://x" }] },
      }),
    TeamPersistError,
  );
});
