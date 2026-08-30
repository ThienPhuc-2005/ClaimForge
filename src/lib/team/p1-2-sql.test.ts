import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { PGlite } from "@electric-sql/pglite";
import { unlockBootstrap } from "./context.ts";
import { bootstrapTenant } from "./repo.ts";
import { wrapPgPool, wrapPglite } from "./sql.ts";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "../../..");
const LAB_SQL = readFileSync(join(root, "migrations/0002_lab_revoke.sql"), "utf8");
const TEAM_SQL = readFileSync(join(root, "migrations/0003_team_isolation.sql"), "utf8");
const OIDC_SQL = readFileSync(join(root, "migrations/0004_team_oidc_sessions.sql"), "utf8");
const SECRET = "test-bootstrap-secret-1";

async function openP12() {
  const pg = new PGlite();
  await pg.waitReady;
  await pg.exec(LAB_SQL);
  await pg.exec(TEAM_SQL);
  await pg.exec(OIDC_SQL);
  return { pg, sql: wrapPglite(pg as never) };
}

test("0004 applies after 0003 and creates pending plus session tables", async () => {
  const { pg } = await openP12();
  const pending = await pg.query<{ rel: string | null }>("SELECT to_regclass('public.team_oidc_pending') AS rel");
  const session = await pg.query<{ rel: string | null }>("SELECT to_regclass('public.team_session') AS rel");
  assert.ok(pending.rows[0]?.rel);
  assert.ok(session.rows[0]?.rel);
});

test("failed 0004 transaction leaves no P1.2 tables and keeps 0003", async () => {
  const pg = new PGlite();
  await pg.waitReady;
  await pg.exec(LAB_SQL);
  await pg.exec(TEAM_SQL);
  try {
    await pg.transaction(async (tx) => {
      await tx.exec(OIDC_SQL);
      await tx.exec("CREATE TABLE team_oidc_orphan_should_not_exist (id text)");
      throw new Error("injected failure");
    });
  } catch (err) {
    assert.equal((err as Error).message, "injected failure");
  }
  const pending = await pg.query<{ rel: string | null }>("SELECT to_regclass('public.team_oidc_pending') AS rel");
  const session = await pg.query<{ rel: string | null }>("SELECT to_regclass('public.team_session') AS rel");
  const orphan = await pg.query<{ rel: string | null }>(
    "SELECT to_regclass('public.team_oidc_orphan_should_not_exist') AS rel",
  );
  const tenant = await pg.query<{ rel: string | null }>("SELECT to_regclass('public.team_tenant') AS rel");
  assert.equal(pending.rows[0]?.rel, null);
  assert.equal(session.rows[0]?.rel, null);
  assert.equal(orphan.rows[0]?.rel, null);
  assert.ok(tenant.rows[0]?.rel);
});

test("session row requires tenant_id and a live membership", async () => {
  const { sql } = await openP12();
  const boot = await bootstrapTenant(sql, unlockBootstrap(SECRET, SECRET), {
    slug: "acme",
    name: "Acme",
    ownerUserKey: "alice",
  });
  await assert.rejects(
    () =>
      sql.query(
        "INSERT INTO team_session (id, token_hash, user_key, expires_at) VALUES ($1, $2, $3, NOW() + INTERVAL '1 hour')",
        ["s1", "hash1", "alice"],
      ),
    /null value|not-null|violates/i,
  );
  await assert.rejects(
    () =>
      sql.query(
        "INSERT INTO team_session (id, token_hash, tenant_id, user_key, expires_at) VALUES ($1, $2, $3, $4, NOW() + INTERVAL '1 hour')",
        ["s2", "hash2", boot.tenant.id, "nobody"],
      ),
    /foreign key|violates/i,
  );
  await sql.query(
    "INSERT INTO team_session (id, token_hash, tenant_id, user_key, expires_at) VALUES ($1, $2, $3, $4, NOW() + INTERVAL '1 hour')",
    ["s3", "hash3", boot.tenant.id, "alice"],
  );
  const rows = await sql.query<{ id: string }>("SELECT id FROM team_session WHERE id = $1", ["s3"]);
  assert.equal(rows[0]?.id, "s3");
});

test("deleting a member cascades team_session rows", async () => {
  const { sql } = await openP12();
  const a = await bootstrapTenant(sql, unlockBootstrap(SECRET, SECRET), {
    slug: "acme",
    name: "Acme",
    ownerUserKey: "alice",
  });
  await sql.query("INSERT INTO team_member (tenant_id, user_key, role) VALUES ($1, $2, $3)", [
    a.tenant.id,
    "carol",
    "analyst",
  ]);
  await sql.query(
    "INSERT INTO team_session (id, token_hash, tenant_id, user_key, expires_at) VALUES ($1, $2, $3, $4, NOW() + INTERVAL '1 hour')",
    ["s-carol", "hash-carol", a.tenant.id, "carol"],
  );
  await sql.query("DELETE FROM team_member WHERE tenant_id = $1 AND user_key = $2", [a.tenant.id, "carol"]);
  const left = await sql.query<{ n: string }>("SELECT COUNT(*)::text AS n FROM team_session WHERE id = $1", [
    "s-carol",
  ]);
  assert.equal(left[0]?.n, "0");
});

test("Neon adapter runs BEGIN, queries, and COMMIT on one checked-out client", async () => {
  const log: string[] = [];
  let connects = 0;
  const pool = {
    query: async (text: string) => {
      log.push(`pool:${text}`);
      return { rows: [] };
    },
    connect: async () => {
      connects += 1;
      const name = `c${connects}`;
      return {
        query: async (text: string) => {
          log.push(`${name}:${text.split(/\s+/)[0]}`);
          return { rows: [] };
        },
        release: () => {
          log.push(`${name}:release`);
        },
      };
    },
  };
  const sql = wrapPgPool(pool);
  await sql.transaction(async (tx) => {
    await tx.query("INSERT INTO team_session (id) VALUES ($1)", ["x"]);
    await tx.query("SELECT 1", []);
  });
  assert.equal(connects, 1);
  assert.deepEqual(log, ["c1:BEGIN", "c1:INSERT", "c1:SELECT", "c1:COMMIT", "c1:release"]);
  await sql.query("SELECT 2", []);
  assert.equal(log.includes("pool:SELECT 2"), true);
});

test("Neon nested transaction uses SAVEPOINT on the same client", async () => {
  const log: string[] = [];
  const pool = {
    query: async (text: string) => {
      log.push(`pool:${text}`);
      return { rows: [] };
    },
    connect: async () => ({
      query: async (text: string) => {
        log.push(`c1:${text}`);
        return { rows: [] };
      },
      release: () => log.push("c1:release"),
    }),
  };
  const sql = wrapPgPool(pool);
  await sql.transaction(async (tx) => {
    await tx.transaction(async (inner) => {
      await inner.query("INSERT INTO team_oidc_pending (state_hash) VALUES ($1)", ["abc"]);
    });
  });
  assert.equal(log[0], "c1:BEGIN");
  assert.ok(log.some((line) => line.startsWith("c1:SAVEPOINT ")));
  assert.ok(log.some((line) => line.startsWith("c1:RELEASE SAVEPOINT ")));
  assert.ok(log.some((line) => line.startsWith("c1:INSERT INTO team_oidc_pending")));
  assert.equal(log[log.length - 2], "c1:COMMIT");
  assert.equal(
    log.filter((line) => line.startsWith("pool:")).length,
    0,
  );
});
