import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { PGlite } from "@electric-sql/pglite";
import { DEFAULT_POLICY } from "../claimforge/policy.ts";
import { appendAuditEvent, assertAuditDetail, listAudit } from "./audit.ts";
import { unlockBootstrap } from "./context.ts";
import { TeamIsolationError, TeamNotFoundError, TeamPersistError, TeamValidationError } from "./errors.ts";
import {
  addMember,
  bootstrapTenant,
  createWorkspace,
  listMembers,
  removeMember,
  resolveTenantContext,
  updateWorkspaceCollab,
} from "./repo.ts";
import { wrapPglite } from "./sql.ts";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "../../..");
const LAB_SQL = readFileSync(join(root, "migrations/0002_lab_revoke.sql"), "utf8");
const TEAM_SQL = readFileSync(join(root, "migrations/0003_team_isolation.sql"), "utf8");
const OIDC_SQL = readFileSync(join(root, "migrations/0004_team_oidc_sessions.sql"), "utf8");
const AUDIT_SQL = readFileSync(join(root, "migrations/0005_team_audit.sql"), "utf8");
const SECRET = "test-bootstrap-secret-1";

async function openP14() {
  const pg = new PGlite();
  await pg.waitReady;
  await pg.exec(LAB_SQL);
  await pg.exec(TEAM_SQL);
  await pg.exec(OIDC_SQL);
  await pg.exec(AUDIT_SQL);
  return { pg, sql: wrapPglite(pg as never) };
}

function operator() {
  return unlockBootstrap(SECRET, SECRET);
}

test("team_audit UPDATE is rejected (append-only)", async () => {
  const { pg, sql } = await openP14();
  const a = await bootstrapTenant(sql, operator(), { slug: "acme", name: "Acme", ownerUserKey: "alice" });
  await addMember(sql, a.context, { userKey: "bob", role: "analyst" });
  const events = await listAudit(sql, a.context);
  assert.equal(events.length, 1);
  await assert.rejects(
    () => pg.query("UPDATE team_audit SET actor_user_key = $1 WHERE id = $2", ["eve", events[0]!.id]),
    /append-only/i,
  );
  const again = await listAudit(sql, a.context);
  assert.equal(again[0]?.actorUserKey, "alice");
});

test("deleting a member does not erase audit rows", async () => {
  const { sql } = await openP14();
  const a = await bootstrapTenant(sql, operator(), { slug: "acme", name: "Acme", ownerUserKey: "alice" });
  await addMember(sql, a.context, { userKey: "bob", role: "admin" });
  const bob = await resolveTenantContext(sql, "bob", a.tenant.id);
  await addMember(sql, bob, { userKey: "carol", role: "analyst" });
  await removeMember(sql, a.context, "bob");
  assert.equal((await listMembers(sql, a.context)).some((m) => m.userKey === "bob"), false);
  const events = await listAudit(sql, a.context);
  assert.equal(events.some((e) => e.action === "member.add" && e.targetId === "bob"), true);
  assert.equal(events.some((e) => e.action === "member.add" && e.actorUserKey === "bob" && e.targetId === "carol"), true);
  assert.equal(events.some((e) => e.action === "member.remove" && e.targetId === "bob"), true);
});

test("caller actorUserKey is rejected; actor is the live member row", async () => {
  const { sql } = await openP14();
  const a = await bootstrapTenant(sql, operator(), { slug: "acme", name: "Acme", ownerUserKey: "alice" });
  await assert.rejects(
    () =>
      addMember(sql, a.context, {
        userKey: "bob",
        role: "analyst",
        actorUserKey: "eve",
      } as { userKey: string; role: "analyst" }),
    TeamIsolationError,
  );
  await addMember(sql, a.context, { userKey: "bob", role: "admin" });
  const bob = await resolveTenantContext(sql, "bob", a.tenant.id);
  assert.equal(bob.role, "admin");
  await sql.query("UPDATE team_member SET role = $3 WHERE tenant_id = $1 AND user_key = $2", [
    a.tenant.id,
    "bob",
    "lead",
  ]);
  const ws = await createWorkspace(sql, bob, { name: "desk" });
  const events = await listAudit(sql, a.context);
  const created = events.find((e) => e.action === "workspace.create" && e.targetId === ws.id);
  assert.equal(created?.actorUserKey, "bob");
  assert.equal(created?.actorRole, "lead");
  assert.notEqual(created?.actorRole, bob.role);
});

test("audit schema omits IP and User-Agent; detail with ip/sha256 is rejected", async () => {
  const { pg, sql } = await openP14();
  const cols = await pg.query<{ column_name: string }>(
    "SELECT column_name FROM information_schema.columns WHERE table_name = 'team_audit'",
  );
  const names = cols.rows.map((r) => r.column_name.toLowerCase());
  assert.equal(names.some((n) => n.includes("ip") || n.includes("agent") || n === "ua"), false);
  const hashed = createHash("sha256").update("127.0.0.1", "utf8").digest("hex");
  assert.throws(() => assertAuditDetail("workspace.delete", { ip: "127.0.0.1" }), TeamPersistError);
  assert.throws(() => assertAuditDetail("workspace.delete", { ip_hash: hashed }), TeamPersistError);
  assert.throws(() => assertAuditDetail("workspace.delete", { userAgent: "Mozilla/5.0" }), TeamPersistError);
  const a = await bootstrapTenant(sql, operator(), { slug: "acme", name: "Acme", ownerUserKey: "alice" });
  await addMember(sql, a.context, { userKey: "bob", role: "analyst" });
  const json = JSON.stringify(await listAudit(sql, a.context));
  assert.equal(json.includes("127.0.0.1"), false);
  assert.equal(json.includes(hashed), false);
});

test("audit detail rejects capture bodies and JWKS material", async () => {
  assert.throws(
    () => assertAuditDetail("collab.update", { fields: ["policy"], aRaw: "GET / HTTP/1.1" }),
    TeamPersistError,
  );
  assert.throws(
    () =>
      assertAuditDetail("collab.update", {
        fields: ["policy"],
        jwt: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhIn0.sig",
      }),
    TeamPersistError,
  );
  assert.throws(
    () => assertAuditDetail("member.add", { role: "analyst", jwks: { keys: [{ kty: "RSA", n: "aaaa", e: "AQAB" }] } }),
    TeamPersistError,
  );
  const compact = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhIn0.signaturevalue";
  assert.throws(() => assertAuditDetail("workspace.create", { name: compact }), TeamPersistError);
});

test("listAudit is tenant-scoped; other tenant does not see events", async () => {
  const { sql } = await openP14();
  const a = await bootstrapTenant(sql, operator(), { slug: "acme", name: "Acme", ownerUserKey: "alice" });
  const b = await bootstrapTenant(sql, operator(), { slug: "beta", name: "Beta", ownerUserKey: "bob" });
  await addMember(sql, a.context, { userKey: "carol", role: "analyst" });
  const fromA = await listAudit(sql, a.context);
  const fromB = await listAudit(sql, b.context);
  assert.equal(fromA.some((e) => e.targetId === "carol"), true);
  assert.equal(fromB.some((e) => e.targetId === "carol"), false);
  assert.equal(
    fromA.every((e) => e.tenantId === a.tenant.id),
    true,
  );
  await assert.rejects(
    () => listAudit(sql, b.context, { tenantId: a.tenant.id } as { limit?: number }),
    TeamIsolationError,
  );
});

test("failed member add does not insert an audit row", async () => {
  const { sql } = await openP14();
  const a = await bootstrapTenant(sql, operator(), { slug: "acme", name: "Acme", ownerUserKey: "alice" });
  await addMember(sql, a.context, { userKey: "bob", role: "analyst" });
  const before = (await listAudit(sql, a.context)).length;
  await assert.rejects(() => addMember(sql, a.context, { userKey: "bob", role: "lead" }), TeamValidationError);
  assert.equal((await listAudit(sql, a.context)).length, before);
  await assert.rejects(() => removeMember(sql, a.context, "nobody"), TeamNotFoundError);
  assert.equal((await listAudit(sql, a.context)).length, before);
});

test("0005 is additive; failed 0005 rolls back and keeps 0003/0004; 0003/0004 have no audit table", async () => {
  assert.doesNotMatch(TEAM_SQL, /CREATE TABLE team_audit/i);
  assert.doesNotMatch(OIDC_SQL, /CREATE TABLE team_audit/i);
  assert.match(AUDIT_SQL, /CREATE TABLE team_audit/);
  assert.doesNotMatch(AUDIT_SQL, /CREATE TABLE team_audit \([^;]*(?:ip_hash|user_agent)\b/i);
  const pg = new PGlite();
  await pg.waitReady;
  await pg.exec(LAB_SQL);
  await pg.exec(TEAM_SQL);
  await pg.exec(OIDC_SQL);
  try {
    await pg.transaction(async (tx) => {
      await tx.exec(AUDIT_SQL);
      await tx.exec("CREATE TABLE team_audit_orphan_should_not_exist (id text)");
      throw new Error("injected failure");
    });
  } catch (err) {
    assert.equal((err as Error).message, "injected failure");
  }
  const audit = await pg.query<{ rel: string | null }>("SELECT to_regclass('public.team_audit') AS rel");
  const orphan = await pg.query<{ rel: string | null }>(
    "SELECT to_regclass('public.team_audit_orphan_should_not_exist') AS rel",
  );
  const tenant = await pg.query<{ rel: string | null }>("SELECT to_regclass('public.team_tenant') AS rel");
  const session = await pg.query<{ rel: string | null }>("SELECT to_regclass('public.team_session') AS rel");
  assert.equal(audit.rows[0]?.rel, null);
  assert.equal(orphan.rows[0]?.rel, null);
  assert.ok(tenant.rows[0]?.rel);
  assert.ok(session.rows[0]?.rel);
});

test("collab audit stores field names not policy/review/report bodies", async () => {
  const { sql } = await openP14();
  const a = await bootstrapTenant(sql, operator(), { slug: "acme", name: "Acme", ownerUserKey: "alice" });
  const ws = await createWorkspace(sql, a.context, { name: "desk" });
  await updateWorkspaceCollab(sql, a.context, ws.id, {
    policy: DEFAULT_POLICY,
    review: { f1: "confirmed" },
  });
  const events = await listAudit(sql, a.context);
  const collab = events.find((e) => e.action === "collab.update");
  assert.deepEqual(collab?.detail, { fields: ["policy", "review"] });
  const blob = JSON.stringify(collab);
  assert.equal(blob.includes("publicPatterns"), false);
  assert.equal(blob.includes("confirmed"), false);
  assert.equal("policy" in (collab?.detail ?? {}), false);
});

test("forged context cannot append or list audit", async () => {
  const { sql } = await openP14();
  const a = await bootstrapTenant(sql, operator(), { slug: "acme", name: "Acme", ownerUserKey: "alice" });
  const fake = { tenantId: a.tenant.id, userKey: "alice", role: "owner" };
  await assert.rejects(
    () =>
      appendAuditEvent(sql, fake as never, {
        action: "member.add",
        targetKind: "member",
        targetId: "eve",
        detail: { role: "viewer" },
      }),
    TeamIsolationError,
  );
  await assert.rejects(() => listAudit(sql, fake as never), TeamIsolationError);
});
