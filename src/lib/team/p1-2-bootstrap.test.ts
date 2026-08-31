import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { PGlite } from "@electric-sql/pglite";
import {
  formatBootstrapOutput,
  parseTeamBootstrapArgs,
  requireOperatorBootstrapEnv,
  runTeamBootstrap,
  safeBootstrapErrorMessage,
} from "./bootstrap-cli.ts";
import { TeamBootstrapError, TeamValidationError } from "./errors.ts";
import { oidcUserKey } from "./oidc-user-key.ts";
import { wrapPglite } from "./sql.ts";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "../../..");
const LAB_SQL = readFileSync(join(root, "migrations/0002_lab_revoke.sql"), "utf8");
const TEAM_SQL = readFileSync(join(root, "migrations/0003_team_isolation.sql"), "utf8");
const OIDC_SQL = readFileSync(join(root, "migrations/0004_team_oidc_sessions.sql"), "utf8");
const SCRIPT = join(root, "scripts/team-bootstrap.mjs");
const SECRET = "test-bootstrap-secret-1";
const ISS = "https://idp-bootstrap.example";
const SUB = "raw-oidc-sub-value-do-not-log";
const ARGS = ["--slug", "acme", "--name", "Acme", "--issuer", ISS, "--sub", SUB];

function expectedUserKey(iss = ISS, sub = SUB): string {
  return "oidc:" + createHash("sha256").update(JSON.stringify([iss, sub]), "utf8").digest("hex");
}

async function openMigrated() {
  const pg = new PGlite();
  await pg.waitReady;
  await pg.exec(LAB_SQL);
  await pg.exec(TEAM_SQL);
  await pg.exec(OIDC_SQL);
  return { pg, sql: wrapPglite(pg as never) };
}

function pgliteOpenSql(pg: PGlite) {
  return async () => ({
    sql: wrapPglite(pg as never),
    close: async () => {},
  });
}

function capture() {
  const stdout: string[] = [];
  const stderr: string[] = [];
  return {
    stdout,
    stderr,
    log: (line: string) => stdout.push(line),
    error: (line: string) => stderr.push(line),
    text() {
      return `${stdout.join("\n")}\n${stderr.join("\n")}`;
    },
  };
}

function assertNoSecrets(text: string) {
  assert.equal(text.includes(SECRET), false);
  assert.equal(text.includes(SUB), false);
  assert.equal(text.includes("confidential-client-secret"), false);
  assert.equal(/Bearer |eyJ[A-Za-z0-9_-]+\./.test(text), false);
}

test("operator bootstrap CLI refuses HTTP, PGLite, and argv secrets", () => {
  const src = readFileSync(join(here, "bootstrap-cli.ts"), "utf8");
  const entry = readFileSync(SCRIPT, "utf8");
  assert.equal(src.includes("getTeamSql"), false);
  assert.equal(src.includes("getPglite"), false);
  assert.equal(src.includes("wrapPglite"), false);
  assert.equal(entry.includes("getTeamSql"), false);
  assert.equal(entry.includes("getPglite"), false);
  assert.equal(entry.includes("wrapPglite"), false);
  assert.match(src, /wrapPgPool/);
  assert.match(src, /import\("pg"\)/);
  assert.doesNotMatch(src, /createServerFn|Request|Response/);
  assert.equal(readdirSync(join(root, "src/routes/api/team")).includes("tenants.ts"), false);
  assert.equal(readdirSync(join(root, "src/routes/api/team")).includes("bootstrap.ts"), false);
  const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8")) as {
    scripts: Record<string, string>;
  };
  assert.match(pkg.scripts["team:bootstrap"] ?? "", /team-bootstrap\.mjs/);

  assert.throws(() => parseTeamBootstrapArgs([...ARGS, "--secret", SECRET]), TeamBootstrapError);
  assert.throws(
    () => parseTeamBootstrapArgs(["--bootstrap-secret", SECRET, ...ARGS]),
    TeamBootstrapError,
  );
  assert.throws(() => parseTeamBootstrapArgs(["--token", "abc", ...ARGS]), TeamBootstrapError);
  assert.throws(
    () => requireOperatorBootstrapEnv({ CLAIMFORGE_TEAM_BOOTSTRAP_SECRET: SECRET }),
    TeamBootstrapError,
  );
  assert.throws(
    () =>
      requireOperatorBootstrapEnv({
        DATABASE_URL: "   ",
        CLAIMFORGE_TEAM_BOOTSTRAP_SECRET: SECRET,
      }),
    /DATABASE_URL is required/,
  );
  assert.throws(
    () => requireOperatorBootstrapEnv({ DATABASE_URL: "postgres://claimforge" }),
    /bootstrap is not configured/,
  );
});

test("operator bootstrap CLI prints only tenant id, slug, and user_key", async () => {
  const { pg, sql } = await openMigrated();
  const io = capture();
  const opened: string[] = [];
  const code = await runTeamBootstrap(ARGS, { DATABASE_URL: "postgres://operator/claimforge", CLAIMFORGE_TEAM_BOOTSTRAP_SECRET: SECRET }, {
    openSql: async (databaseUrl) => {
      opened.push(databaseUrl);
      return pgliteOpenSql(pg)();
    },
    log: io.log,
    error: io.error,
  });
  assert.equal(code, 0);
  assert.deepEqual(opened, ["postgres://operator/claimforge"]);
  assert.equal(io.stderr.length, 0);
  assert.equal(io.stdout.length, 1);
  const parsed = JSON.parse(io.stdout[0]!) as { tenantId: string; slug: string; userKey: string };
  assert.equal(Object.keys(parsed).sort().join(","), "slug,tenantId,userKey");
  assert.equal(parsed.slug, "acme");
  assert.equal(parsed.userKey, expectedUserKey());
  assert.equal(parsed.userKey, oidcUserKey(ISS, SUB));
  assert.match(parsed.tenantId, /^[0-9a-f-]{36}$/i);
  assert.equal(formatBootstrapOutput(parsed), io.stdout[0]);
  assertNoSecrets(io.text());
  assert.equal(io.text().includes(ISS), false);
  const members = await sql.query<{ user_key: string; role: string }>(
    "SELECT user_key, role FROM team_member WHERE tenant_id = $1",
    [parsed.tenantId],
  );
  assert.deepEqual(members, [{ user_key: expectedUserKey(), role: "owner" }]);
});

test("operator bootstrap CLI fail-closes on missing env, unmigrated schema, and duplicate slug", async () => {
  assert.throws(() => parseTeamBootstrapArgs([]), /slug is required/);
  assert.throws(() => parseTeamBootstrapArgs(["--slug", "acme"]), /name is required/);
  assert.throws(
    () => parseTeamBootstrapArgs(["--slug", "acme", "--name", "Acme", "--issuer", ISS]),
    /sub is required/,
  );
  assert.throws(() => parseTeamBootstrapArgs(["--slug", "A", ...ARGS.slice(2)]), TeamValidationError);
  assert.throws(() => parseTeamBootstrapArgs([...ARGS, "--extra", "1"]), /unknown argument/);

  const missingUrl = capture();
  assert.equal(
    await runTeamBootstrap(ARGS, { CLAIMFORGE_TEAM_BOOTSTRAP_SECRET: SECRET }, missingUrl),
    1,
  );
  assert.match(missingUrl.stderr.join("\n"), /DATABASE_URL is required/);
  assert.equal(missingUrl.stdout.length, 0);
  assertNoSecrets(missingUrl.text());

  const missingSecret = capture();
  assert.equal(
    await runTeamBootstrap(ARGS, { DATABASE_URL: "postgres://operator/claimforge" }, missingSecret),
    1,
  );
  assert.match(missingSecret.stderr.join("\n"), /bootstrap is not configured/);
  assertNoSecrets(missingSecret.text());

  const shortSecret = capture();
  const { pg: empty } = await (async () => {
    const pg = new PGlite();
    await pg.waitReady;
    return { pg };
  })();
  assert.equal(
    await runTeamBootstrap(
      ARGS,
      { DATABASE_URL: "postgres://operator/claimforge", CLAIMFORGE_TEAM_BOOTSTRAP_SECRET: "short" },
      { openSql: pgliteOpenSql(empty), ...shortSecret },
    ),
    1,
  );
  assert.match(shortSecret.stderr.join("\n"), /bootstrap is not configured/);
  assertNoSecrets(shortSecret.text());

  const unmigrated = capture();
  const bare = new PGlite();
  await bare.waitReady;
  assert.equal(
    await runTeamBootstrap(
      ARGS,
      { DATABASE_URL: "postgres://operator/claimforge", CLAIMFORGE_TEAM_BOOTSTRAP_SECRET: SECRET },
      { openSql: pgliteOpenSql(bare), ...unmigrated },
    ),
    1,
  );
  assert.match(unmigrated.stderr.join("\n"), /team schema is not migrated/);
  assert.equal(unmigrated.stdout.length, 0);
  assertNoSecrets(unmigrated.text());

  const { pg } = await openMigrated();
  const first = capture();
  assert.equal(
    await runTeamBootstrap(
      ARGS,
      { DATABASE_URL: "postgres://operator/claimforge", CLAIMFORGE_TEAM_BOOTSTRAP_SECRET: SECRET },
      { openSql: pgliteOpenSql(pg), ...first },
    ),
    0,
  );
  const dup = capture();
  assert.equal(
    await runTeamBootstrap(
      ["--slug", "acme", "--name", "Acme 2", "--issuer", ISS, "--sub", "other-sub"],
      { DATABASE_URL: "postgres://operator/claimforge", CLAIMFORGE_TEAM_BOOTSTRAP_SECRET: SECRET },
      { openSql: pgliteOpenSql(pg), ...dup },
    ),
    1,
  );
  assert.match(dup.stderr.join("\n"), /tenant already exists/);
  assert.equal(dup.stdout.length, 0);
  assert.equal(dup.text().includes("other-sub"), false);
  assertNoSecrets(dup.text());

  const pgError = Object.assign(new Error(`duplicate key value violates unique constraint "team_tenant_slug_key" DETAIL: Key (slug)=(acme) already exists. sub=${SUB}`), {
    code: "23505",
  });
  assert.equal(safeBootstrapErrorMessage(pgError), "bootstrap failed");
  assert.equal(new TeamBootstrapError("tenant already exists") instanceof Error, true);
});

test("operator bootstrap CLI process fail-closes without DATABASE_URL and does not echo secrets", () => {
  const env = { ...process.env };
  delete env.DATABASE_URL;
  delete env.CLAIMFORGE_TEAM_BOOTSTRAP_SECRET;
  const missing = spawnSync(process.execPath, ["--experimental-strip-types", SCRIPT, ...ARGS], {
    encoding: "utf8",
    env,
  });
  assert.equal(missing.status, 1);
  assert.match(missing.stderr, /DATABASE_URL is required/);
  assert.equal(missing.stdout, "");
  assertNoSecrets(`${missing.stdout}\n${missing.stderr}`);

  const secretArg = spawnSync(
    process.execPath,
    ["--experimental-strip-types", SCRIPT, "--secret", SECRET, ...ARGS],
    {
      encoding: "utf8",
      env: { ...env, DATABASE_URL: "postgres://operator/claimforge" },
    },
  );
  assert.equal(secretArg.status, 1);
  assert.match(secretArg.stderr, /bootstrap secret must come from the environment/);
  assertNoSecrets(`${secretArg.stdout}\n${secretArg.stderr}`);
});
