import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { PGlite } from "@electric-sql/pglite";
import { unlockBootstrap } from "./context.ts";
import { TEAM_SESSION_COOKIE } from "./cookie.ts";
import { handleTeamSession } from "./oidc-http.ts";
import {
  handleTeamMembersDelete,
  handleTeamMembersGet,
  handleTeamMembersPatch,
  handleTeamMembersPost,
} from "./rbac-http.ts";
import { addMember, bootstrapTenant, listMembers, resolveTenantContext } from "./repo.ts";
import { mintTeamSession } from "./session.ts";
import { wrapPglite } from "./sql.ts";
import type { TeamSql } from "./types.ts";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "../../..");
const LAB_SQL = readFileSync(join(root, "migrations/0002_lab_revoke.sql"), "utf8");
const TEAM_SQL = readFileSync(join(root, "migrations/0003_team_isolation.sql"), "utf8");
const OIDC_SQL = readFileSync(join(root, "migrations/0004_team_oidc_sessions.sql"), "utf8");
const SECRET = "test-bootstrap-secret-1";
const ENV = {
  CLAIMFORGE_TEAM_OIDC_ISSUER: "https://idp-rbac.example",
  CLAIMFORGE_TEAM_OIDC_CLIENT_ID: "claimforge",
  CLAIMFORGE_TEAM_OIDC_CLIENT_SECRET: "confidential-client-secret-value",
  CLAIMFORGE_TEAM_OIDC_REDIRECT_URI: "https://app.example/api/team/oidc/callback",
  CLAIMFORGE_TEAM_OIDC_AUTHORIZATION_ENDPOINT: "https://idp-rbac.example/authorize",
  CLAIMFORGE_TEAM_OIDC_TOKEN_ENDPOINT: "https://idp-rbac.example/token",
  CLAIMFORGE_TEAM_OIDC_JWKS_URI: "https://idp-rbac.example/jwks",
  CLAIMFORGE_TEAM_OIDC_ALLOWED_HOSTS: "idp-rbac.example",
  CLAIMFORGE_TEAM_SEAL_KEY: "claimforge-team-seal-key-32bytes!",
};

async function openSql() {
  const pg = new PGlite();
  await pg.waitReady;
  await pg.exec(LAB_SQL);
  await pg.exec(TEAM_SQL);
  await pg.exec(OIDC_SQL);
  return { pg, sql: wrapPglite(pg as never) };
}

function operator() {
  return unlockBootstrap(SECRET, SECRET);
}

function cookieHeader(token: string): string {
  return `${TEAM_SESSION_COOKIE}=${token}`;
}

function req(method: string, url: string, token?: string, body?: unknown, origin?: string): Request {
  const headers: Record<string, string> = {};
  if (token) headers.cookie = cookieHeader(token);
  if (body !== undefined) headers["content-type"] = "application/json";
  if (origin) headers.origin = origin;
  return new Request(url, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

const MEMBERS = "https://app.example/api/team/members";

async function ownerSession(sql: TeamSql) {
  const boot = await bootstrapTenant(sql, operator(), { slug: "acme", name: "Acme", ownerUserKey: "alice" });
  const minted = await mintTeamSession(sql, boot.context);
  return { ...boot, token: minted.token };
}

test("GET /api/team/members lists the session tenant only", async () => {
  const { sql } = await openSql();
  const a = await ownerSession(sql);
  await bootstrapTenant(sql, operator(), { slug: "beta", name: "Beta", ownerUserKey: "bob" });
  await addMember(sql, a.context, { userKey: "carol", role: "analyst" });
  const res = await handleTeamMembersGet(req("GET", MEMBERS, a.token), { sql, env: ENV });
  assert.equal(res.status, 200);
  assert.equal(res.headers.get("cache-control"), "no-store");
  const body = (await res.json()) as { members: Array<{ userKey: string; role: string; tenantId?: string }> };
  assert.deepEqual(
    body.members.map((m) => m.userKey).sort(),
    ["alice", "carol"],
  );
  assert.equal(
    body.members.every((m) => !("tenantId" in m) && !("tenant_id" in m)),
    true,
  );
});

test("viewer POST /api/team/members is 403", async () => {
  const { sql } = await openSql();
  const a = await ownerSession(sql);
  await addMember(sql, a.context, { userKey: "view", role: "viewer" });
  const viewer = await resolveTenantContext(sql, "view", a.tenant.id);
  const { token } = await mintTeamSession(sql, viewer);
  const res = await handleTeamMembersPost(req("POST", MEMBERS, token, { userKey: "eve", role: "analyst" }), {
    sql,
    env: ENV,
  });
  assert.equal(res.status, 403);
  assert.deepEqual(await res.json(), { error: "forbidden" });
  assert.equal((await listMembers(sql, a.context)).some((m) => m.userKey === "eve"), false);
});

test("admin POST cannot assign owner; JWT-shaped role in body is just another role string", async () => {
  const { sql } = await openSql();
  const a = await ownerSession(sql);
  await addMember(sql, a.context, { userKey: "ada", role: "admin" });
  const admin = await resolveTenantContext(sql, "ada", a.tenant.id);
  const { token } = await mintTeamSession(sql, admin);
  const ownerAttempt = await handleTeamMembersPost(
    req("POST", MEMBERS, token, { userKey: "root2", role: "owner" }),
    { sql, env: ENV },
  );
  assert.equal(ownerAttempt.status, 403);
  const created = await handleTeamMembersPost(
    req("POST", MEMBERS, token, { userKey: "n1", role: "analyst" }),
    { sql, env: ENV },
  );
  assert.equal(created.status, 201);
});

test("caller tenant_id on member body is rejected", async () => {
  const { sql } = await openSql();
  const a = await ownerSession(sql);
  const res = await handleTeamMembersPost(
    req("POST", MEMBERS, a.token, { userKey: "eve", role: "viewer", tenant_id: "spoof" }),
    { sql, env: ENV },
  );
  assert.equal(res.status, 400);
  assert.deepEqual(await res.json(), { error: "invalid" });
});

test("cross-origin member mutation is 401", async () => {
  const { sql } = await openSql();
  const a = await ownerSession(sql);
  const res = await handleTeamMembersPost(
    req("POST", MEMBERS, a.token, { userKey: "eve", role: "viewer" }, "https://evil.example"),
    { sql, env: ENV },
  );
  assert.equal(res.status, 401);
});

test("PATCH and DELETE enforce admin+ and last-owner protection", async () => {
  const { sql } = await openSql();
  const a = await ownerSession(sql);
  await addMember(sql, a.context, { userKey: "ana", role: "analyst" });
  const promoted = await handleTeamMembersPatch(
    req("PATCH", MEMBERS, a.token, { userKey: "ana", role: "lead" }),
    { sql, env: ENV },
  );
  assert.equal(promoted.status, 200);
  const lastOwner = await handleTeamMembersDelete(req("DELETE", `${MEMBERS}?userKey=alice`, a.token), {
    sql,
    env: ENV,
  });
  assert.equal(lastOwner.status, 403);
  const removed = await handleTeamMembersDelete(req("DELETE", `${MEMBERS}?userKey=ana`, a.token), {
    sql,
    env: ENV,
  });
  assert.equal(removed.status, 200);
  assert.equal((await listMembers(sql, a.context)).some((m) => m.userKey === "ana"), false);
});

test("unauthenticated members routes are 401", async () => {
  const { sql } = await openSql();
  const res = await handleTeamMembersGet(req("GET", MEMBERS), { sql, env: ENV });
  assert.equal(res.status, 401);
});

test("analyst and lead cannot escalate via members HTTP", async () => {
  const { sql } = await openSql();
  const a = await ownerSession(sql);
  await addMember(sql, a.context, { userKey: "ana", role: "analyst" });
  await addMember(sql, a.context, { userKey: "lea", role: "lead" });
  const analyst = await resolveTenantContext(sql, "ana", a.tenant.id);
  const lead = await resolveTenantContext(sql, "lea", a.tenant.id);
  const { token: anaTok } = await mintTeamSession(sql, analyst);
  const { token: leaTok } = await mintTeamSession(sql, lead);
  for (const token of [anaTok, leaTok]) {
    const post = await handleTeamMembersPost(req("POST", MEMBERS, token, { userKey: "eve", role: "viewer" }), {
      sql,
      env: ENV,
    });
    assert.equal(post.status, 403);
    const patch = await handleTeamMembersPatch(
      req("PATCH", MEMBERS, token, { userKey: "ana", role: "admin" }),
      { sql, env: ENV },
    );
    assert.equal(patch.status, 403);
    const del = await handleTeamMembersDelete(req("DELETE", `${MEMBERS}?userKey=ana`, token), { sql, env: ENV });
    assert.equal(del.status, 403);
  }
  const listed = await listMembers(sql, a.context);
  assert.equal(listed.some((m) => m.userKey === "eve"), false);
  assert.equal(listed.find((m) => m.userKey === "ana")?.role, "analyst");
});

test("viewer GET members is 200; session JSON still omits role", async () => {
  const { sql } = await openSql();
  const a = await ownerSession(sql);
  await addMember(sql, a.context, { userKey: "view", role: "viewer" });
  const viewer = await resolveTenantContext(sql, "view", a.tenant.id);
  const { token } = await mintTeamSession(sql, viewer);
  const members = await handleTeamMembersGet(req("GET", MEMBERS, token), { sql, env: ENV });
  assert.equal(members.status, 200);
  const body = (await members.json()) as { members: Array<{ userKey: string; role: string }> };
  assert.ok(body.members.some((m) => m.userKey === "alice" && m.role === "owner"));
  const session = await handleTeamSession(req("GET", "https://app.example/api/team/session", token), { sql, env: ENV });
  assert.equal(session.status, 200);
  const me = (await session.json()) as { userKey: string; tenantId: string; role?: unknown };
  assert.equal(me.userKey, "view");
  assert.equal("role" in me, false);
});

test("Bearer JWT is not a Team session; HTTP members is 400", async () => {
  const { sql } = await openSql();
  const jwtReq = new Request(MEMBERS, {
    method: "GET",
    headers: { authorization: "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.e30.sig", role: "owner" },
  });
  const jwt = await handleTeamMembersGet(jwtReq, { sql, env: ENV });
  assert.equal(jwt.status, 401);
  const a = await ownerSession(sql);
  const http = await handleTeamMembersGet(
    new Request("http://app.example/api/team/members", { headers: { cookie: cookieHeader(a.token) } }),
    { sql, env: ENV },
  );
  assert.equal(http.status, 400);
  assert.deepEqual(await http.json(), { error: "oidc requires HTTPS" });
});

test("unknown member delete is 404; invalid role is 400", async () => {
  const { sql } = await openSql();
  const a = await ownerSession(sql);
  const missing = await handleTeamMembersDelete(req("DELETE", `${MEMBERS}?userKey=nobody`, a.token), {
    sql,
    env: ENV,
  });
  assert.equal(missing.status, 404);
  const badRole = await handleTeamMembersPost(
    req("POST", MEMBERS, a.token, { userKey: "eve", role: "superadmin" }),
    { sql, env: ENV },
  );
  assert.equal(badRole.status, 400);
});
