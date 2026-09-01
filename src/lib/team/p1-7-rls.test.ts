import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { PGlite } from "@electric-sql/pglite";
import pg from "pg";
import { unlockBootstrap } from "./context.ts";
import { addMember, bootstrapTenant, createWorkspace, listMembers, listWorkspaces } from "./repo.ts";
import { wrapPgPool, wrapPglite } from "./sql.ts";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "../../..");
const LAB_SQL = readFileSync(join(root, "migrations/0002_lab_revoke.sql"), "utf8");
const TEAM_SQL = readFileSync(join(root, "migrations/0003_team_isolation.sql"), "utf8");
const OIDC_SQL = readFileSync(join(root, "migrations/0004_team_oidc_sessions.sql"), "utf8");
const AUDIT_SQL = readFileSync(join(root, "migrations/0005_team_audit.sql"), "utf8");
const RLS_SQL = readFileSync(join(root, "migrations/0006_team_rls.sql"), "utf8");
const SECRET = "test-bootstrap-secret-1";
const RLS_URL = process.env.CLAIMFORGE_TEAM_RLS_DATABASE_URL?.trim() || "";

async function applyTeam(exec: (sql: string) => Promise<unknown>) {
  await exec(LAB_SQL);
  await exec(TEAM_SQL);
  await exec(OIDC_SQL);
  await exec(AUDIT_SQL);
}

test("0006 is additive; failed 0006 rolls back and keeps 0003/0004/0005; 0003-0005 have no RLS policy", async () => {
  assert.doesNotMatch(TEAM_SQL, /ENABLE ROW LEVEL SECURITY/i);
  assert.doesNotMatch(OIDC_SQL, /ENABLE ROW LEVEL SECURITY/i);
  assert.doesNotMatch(AUDIT_SQL, /ENABLE ROW LEVEL SECURITY/i);
  assert.match(RLS_SQL, /FORCE ROW LEVEL SECURITY/);
  assert.match(RLS_SQL, /claimforge\.tenant_id/);
  assert.doesNotMatch(RLS_SQL, /ALTER TABLE team_session ENABLE/i);
  assert.doesNotMatch(RLS_SQL, /ALTER TABLE team_tenant ENABLE/i);
  const pgLite = new PGlite();
  await pgLite.waitReady;
  await applyTeam((sql) => pgLite.exec(sql));
  try {
    await pgLite.transaction(async (tx) => {
      await tx.exec(RLS_SQL);
      await tx.exec("CREATE TABLE team_rls_orphan_should_not_exist (id text)");
      throw new Error("injected failure");
    });
  } catch (err) {
    assert.equal((err as Error).message, "injected failure");
  }
  const orphan = await pgLite.query<{ rel: string | null }>(
    "SELECT to_regclass('public.team_rls_orphan_should_not_exist') AS rel",
  );
  const tenant = await pgLite.query<{ rel: string | null }>("SELECT to_regclass('public.team_tenant') AS rel");
  const audit = await pgLite.query<{ rel: string | null }>("SELECT to_regclass('public.team_audit') AS rel");
  assert.equal(orphan.rows[0]?.rel, null);
  assert.ok(tenant.rows[0]?.rel);
  assert.ok(audit.rows[0]?.rel);
});

test("PGLite still bootstraps after 0006 DDL (RLS is not claimed on PGLite)", async () => {
  const pgLite = new PGlite();
  await pgLite.waitReady;
  await applyTeam((sql) => pgLite.exec(sql));
  await pgLite.exec(RLS_SQL);
  const sql = wrapPglite(pgLite as never);
  const boot = await bootstrapTenant(sql, unlockBootstrap(SECRET, SECRET), {
    slug: "acme",
    name: "Acme",
    ownerUserKey: "alice",
  });
  await addMember(sql, boot.context, { userKey: "bob", role: "viewer" });
  const members = await listMembers(sql, boot.context);
  assert.equal(members.some((m) => m.userKey === "bob"), true);
});

test("Postgres RLS: missing GUC hides rows; kernel GUC lists only the session tenant", { skip: !RLS_URL }, async () => {
  const admin = new pg.Pool({ connectionString: RLS_URL, max: 2 });
  const db = `claimforge_rls_${process.pid}`;
  try {
    await admin.query(`DROP DATABASE IF EXISTS ${db}`);
    await admin.query(`CREATE DATABASE ${db}`);
    const url = new URL(RLS_URL);
    url.pathname = `/${db}`;
    const owner = new pg.Pool({ connectionString: url.toString(), max: 2 });
    try {
      await applyTeam((sql) => owner.query(sql));
      await owner.query(RLS_SQL);
      const role = `claimforge_rls_app_${process.pid}`;
      await owner.query(`DROP ROLE IF EXISTS ${role}`);
      await owner.query(`CREATE ROLE ${role} LOGIN PASSWORD 'rls-lab' NOSUPERUSER NOBYPASSRLS`);
      await owner.query(`GRANT USAGE ON SCHEMA public TO ${role}`);
      await owner.query(`GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO ${role}`);
      url.username = role;
      url.password = "rls-lab";
      const app = new pg.Pool({ connectionString: url.toString(), max: 2 });
      try {
        const empty = await app.query("SELECT count(*)::int AS n FROM team_workspace");
        assert.equal(empty.rows[0]?.n, 0);
        const sql = wrapPgPool(app);
        const a = await bootstrapTenant(sql, unlockBootstrap(SECRET, SECRET), {
          slug: "acme",
          name: "Acme",
          ownerUserKey: "alice",
        });
        const b = await bootstrapTenant(sql, unlockBootstrap(SECRET, SECRET), {
          slug: "beta",
          name: "Beta",
          ownerUserKey: "zara",
        });
        await createWorkspace(sql, a.context, { name: "desk-a" });
        await createWorkspace(sql, b.context, { name: "desk-b" });
        const listed = await listWorkspaces(sql, a.context);
        assert.deepEqual(
          listed.map((w) => w.name),
          ["desk-a"],
        );
        const leaked = await app.query("SELECT name FROM team_workspace");
        assert.equal(leaked.rows.length, 0);
        const client = await app.connect();
        try {
          await client.query("BEGIN");
          await client.query("SELECT set_config($1, $2, true)", ["claimforge.tenant_id", a.tenant.id]);
          const scoped = await client.query<{ name: string }>("SELECT name FROM team_workspace ORDER BY name");
          assert.deepEqual(
            scoped.rows.map((r) => r.name),
            ["desk-a"],
          );
          await client.query("ROLLBACK");
        } finally {
          client.release();
        }
      } finally {
        await app.end();
      }
    } finally {
      await owner.end();
    }
  } finally {
    await admin.query(`DROP DATABASE IF EXISTS ${db}`).catch(() => {});
    await admin.query(`DROP ROLE IF EXISTS claimforge_rls_app_${process.pid}`).catch(() => {});
    await admin.end();
  }
});
