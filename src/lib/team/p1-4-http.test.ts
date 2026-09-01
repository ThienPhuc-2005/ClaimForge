import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { PGlite } from "@electric-sql/pglite";
import { handleTeamAuditGet } from "./audit-http.ts";
import { unlockBootstrap } from "./context.ts";
import { TEAM_SESSION_COOKIE } from "./cookie.ts";
import { addMember, bootstrapTenant, createWorkspace, listAudit, resolveTenantContext } from "./repo.ts";
import { mintTeamSession } from "./session.ts";
import { wrapPglite } from "./sql.ts";
import type { TeamSql } from "./types.ts";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "../../..");
const LAB_SQL = readFileSync(join(root, "migrations/0002_lab_revoke.sql"), "utf8");
const TEAM_SQL = readFileSync(join(root, "migrations/0003_team_isolation.sql"), "utf8");
const OIDC_SQL = readFileSync(join(root, "migrations/0004_team_oidc_sessions.sql"), "utf8");
const AUDIT_SQL = readFileSync(join(root, "migrations/0005_team_audit.sql"), "utf8");
const SECRET = "test-bootstrap-secret-1";
const ENV = {
  CLAIMFORGE_TEAM_OIDC_ISSUER: "https://idp-audit.example",
  CLAIMFORGE_TEAM_OIDC_CLIENT_ID: "claimforge",
  CLAIMFORGE_TEAM_OIDC_CLIENT_SECRET: "confidential-client-secret-value",
  CLAIMFORGE_TEAM_OIDC_REDIRECT_URI: "https://app.example/api/team/oidc/callback",
  CLAIMFORGE_TEAM_OIDC_AUTHORIZATION_ENDPOINT: "https://idp-audit.example/authorize",
  CLAIMFORGE_TEAM_OIDC_TOKEN_ENDPOINT: "https://idp-audit.example/token",
  CLAIMFORGE_TEAM_OIDC_JWKS_URI: "https://idp-audit.example/jwks",
  CLAIMFORGE_TEAM_OIDC_ALLOWED_HOSTS: "idp-audit.example",
  CLAIMFORGE_TEAM_SEAL_KEY: "claimforge-team-seal-key-32bytes!",
};

const AUDIT = "https://app.example/api/team/audit";

async function openSql() {
  const pg = new PGlite();
  await pg.waitReady;
  await pg.exec(LAB_SQL);
  await pg.exec(TEAM_SQL);
  await pg.exec(OIDC_SQL);
  await pg.exec(AUDIT_SQL);
  return { pg, sql: wrapPglite(pg as never) };
}

function cookieHeader(token: string): string {
  return `${TEAM_SESSION_COOKIE}=${token}`;
}

function req(method: string, url: string, token?: string): Request {
  const headers: Record<string, string> = {};
  if (token) headers.cookie = cookieHeader(token);
  return new Request(url, { method, headers });
}

async function ownerSession(sql: TeamSql) {
  const boot = await bootstrapTenant(sql, unlockBootstrap(SECRET, SECRET), {
    slug: "acme",
    name: "Acme",
    ownerUserKey: "alice",
  });
  const minted = await mintTeamSession(sql, boot.context);
  return { ...boot, token: minted.token };
}

test("GET /api/team/audit is session-bound; tenant_id/actor query rejected; JSON omits tenantId and IP", async () => {
  const { sql } = await openSql();
  const a = await ownerSession(sql);
  await addMember(sql, a.context, { userKey: "bob", role: "viewer" });
  await bootstrapTenant(sql, unlockBootstrap(SECRET, SECRET), {
    slug: "beta",
    name: "Beta",
    ownerUserKey: "other",
  });
  const res = await handleTeamAuditGet(req("GET", AUDIT, a.token), { sql, env: ENV });
  assert.equal(res.status, 200);
  assert.equal(res.headers.get("cache-control"), "no-store");
  const body = (await res.json()) as {
    events: Array<Record<string, unknown>>;
  };
  assert.equal(body.events.some((e) => e.action === "member.add" && e.targetId === "bob"), true);
  assert.equal(
    body.events.every((e) => !("tenantId" in e) && !("tenant_id" in e) && !("ip" in e) && !("userAgent" in e)),
    true,
  );
  const spoofTenant = await handleTeamAuditGet(req("GET", `${AUDIT}?tenant_id=${a.tenant.id}`, a.token), {
    sql,
    env: ENV,
  });
  assert.equal(spoofTenant.status, 400);
  const spoofActor = await handleTeamAuditGet(req("GET", `${AUDIT}?actorUserKey=eve`, a.token), { sql, env: ENV });
  assert.equal(spoofActor.status, 400);
  const anon = await handleTeamAuditGet(req("GET", AUDIT), { sql, env: ENV });
  assert.equal(anon.status, 401);
  const jwt = await handleTeamAuditGet(
    new Request(AUDIT, { headers: { authorization: "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.e30.sig" } }),
    { sql, env: ENV },
  );
  assert.equal(jwt.status, 401);
  const http = await handleTeamAuditGet(
    new Request("http://app.example/api/team/audit", { headers: { cookie: cookieHeader(a.token) } }),
    { sql, env: ENV },
  );
  assert.equal(http.status, 400);
  const viewer = await resolveTenantContext(sql, "bob", a.tenant.id);
  const { token: viewTok } = await mintTeamSession(sql, viewer);
  const asViewer = await handleTeamAuditGet(req("GET", AUDIT, viewTok), { sql, env: ENV });
  assert.equal(asViewer.status, 200);
  const ws = await createWorkspace(sql, a.context, { name: "desk" });
  assert.ok((await listAudit(sql, a.context)).some((e) => e.targetId === ws.id));
});
