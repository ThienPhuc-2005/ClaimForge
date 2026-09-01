import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { PGlite } from "@electric-sql/pglite";
import { DEFAULT_POLICY } from "../claimforge/policy.ts";
import {
  handleTeamCollabGet,
  handleTeamCollabPatch,
  handleTeamWorkspacesDelete,
  handleTeamWorkspacesGet,
  handleTeamWorkspacesPost,
} from "./collab-http.ts";
import { unlockBootstrap } from "./context.ts";
import { TEAM_SESSION_COOKIE } from "./cookie.ts";
import { handleTeamSession } from "./oidc-http.ts";
import { addMember, bootstrapTenant, getCollab, listAudit, listWorkspaces, resolveTenantContext } from "./repo.ts";
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
  CLAIMFORGE_TEAM_OIDC_ISSUER: "https://idp-collab.example",
  CLAIMFORGE_TEAM_OIDC_CLIENT_ID: "claimforge",
  CLAIMFORGE_TEAM_OIDC_CLIENT_SECRET: "confidential-client-secret-value",
  CLAIMFORGE_TEAM_OIDC_REDIRECT_URI: "https://app.example/api/team/oidc/callback",
  CLAIMFORGE_TEAM_OIDC_AUTHORIZATION_ENDPOINT: "https://idp-collab.example/authorize",
  CLAIMFORGE_TEAM_OIDC_TOKEN_ENDPOINT: "https://idp-collab.example/token",
  CLAIMFORGE_TEAM_OIDC_JWKS_URI: "https://idp-collab.example/jwks",
  CLAIMFORGE_TEAM_OIDC_ALLOWED_HOSTS: "idp-collab.example",
  CLAIMFORGE_TEAM_SEAL_KEY: "claimforge-team-seal-key-32bytes!",
};

const WS = "https://app.example/api/team/workspaces";
const COLLAB = "https://app.example/api/team/collab";

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

async function ownerSession(sql: TeamSql, slug = "acme", owner = "alice") {
  const boot = await bootstrapTenant(sql, unlockBootstrap(SECRET, SECRET), {
    slug,
    name: slug,
    ownerUserKey: owner,
  });
  const minted = await mintTeamSession(sql, boot.context);
  return { ...boot, token: minted.token };
}

async function memberToken(sql: TeamSql, tenantId: string, userKey: string) {
  const ctx = await resolveTenantContext(sql, userKey, tenantId);
  const { token } = await mintTeamSession(sql, ctx);
  return token;
}

test("GET /api/team/workspaces lists the session tenant only; JSON omits tenantId", async () => {
  const { sql } = await openSql();
  const a = await ownerSession(sql);
  const b = await ownerSession(sql, "beta", "bob");
  const created = await handleTeamWorkspacesPost(req("POST", WS, a.token, { name: "desk" }), { sql, env: ENV });
  assert.equal(created.status, 201);
  await handleTeamWorkspacesPost(req("POST", WS, b.token, { name: "other" }), { sql, env: ENV });
  const res = await handleTeamWorkspacesGet(req("GET", WS, a.token), { sql, env: ENV });
  assert.equal(res.status, 200);
  assert.equal(res.headers.get("cache-control"), "no-store");
  const body = (await res.json()) as {
    workspaces: Array<{ id: string; name: string; tenantId?: string; tenant_id?: string }>;
  };
  assert.deepEqual(
    body.workspaces.map((w) => w.name),
    ["desk"],
  );
  assert.equal(
    body.workspaces.every((w) => !("tenantId" in w) && !("tenant_id" in w)),
    true,
  );
});

test("cross-tenant collab GET/PATCH is 404; victim row unchanged", async () => {
  const { sql } = await openSql();
  const a = await ownerSession(sql);
  const b = await ownerSession(sql, "beta", "bob");
  const created = await handleTeamWorkspacesPost(req("POST", WS, a.token, { name: "desk" }), { sql, env: ENV });
  const { workspace } = (await created.json()) as { workspace: { id: string } };
  const saved = await handleTeamCollabPatch(
    req("PATCH", COLLAB, a.token, { workspaceId: workspace.id, policy: DEFAULT_POLICY }),
    { sql, env: ENV },
  );
  assert.equal(saved.status, 200);
  const getOther = await handleTeamCollabGet(req("GET", `${COLLAB}?workspaceId=${workspace.id}`, b.token), {
    sql,
    env: ENV,
  });
  assert.equal(getOther.status, 404);
  assert.deepEqual(await getOther.json(), { error: "not found" });
  const patchOther = await handleTeamCollabPatch(
    req("PATCH", COLLAB, b.token, { workspaceId: workspace.id, review: { f1: "confirmed" } }),
    { sql, env: ENV },
  );
  assert.equal(patchOther.status, 404);
  const listed = await handleTeamWorkspacesGet(req("GET", WS, b.token), { sql, env: ENV });
  const { workspaces } = (await listed.json()) as { workspaces: Array<{ id: string }> };
  assert.equal(workspaces.some((w) => w.id === workspace.id), false);
  const victim = await getCollab(sql, a.context, workspace.id);
  assert.equal(victim?.review, null);
  assert.equal(victim?.policy?.version, DEFAULT_POLICY.version);
});

test("viewer GET collab is 200; viewer workspace/collab writes are 403", async () => {
  const { sql } = await openSql();
  const a = await ownerSession(sql);
  await addMember(sql, a.context, { userKey: "view", role: "viewer" });
  const created = await handleTeamWorkspacesPost(req("POST", WS, a.token, { name: "desk" }), { sql, env: ENV });
  const { workspace } = (await created.json()) as { workspace: { id: string } };
  await handleTeamCollabPatch(req("PATCH", COLLAB, a.token, { workspaceId: workspace.id, policy: DEFAULT_POLICY }), {
    sql,
    env: ENV,
  });
  const viewTok = await memberToken(sql, a.tenant.id, "view");
  const get = await handleTeamCollabGet(req("GET", `${COLLAB}?workspaceId=${workspace.id}`, viewTok), {
    sql,
    env: ENV,
  });
  assert.equal(get.status, 200);
  const body = (await get.json()) as { collab: { workspaceId: string; tenantId?: string } | null };
  assert.equal(body.collab?.workspaceId, workspace.id);
  assert.equal(body.collab && "tenantId" in body.collab, false);
  const post = await handleTeamWorkspacesPost(req("POST", WS, viewTok, { name: "nope" }), { sql, env: ENV });
  assert.equal(post.status, 403);
  const patch = await handleTeamCollabPatch(
    req("PATCH", COLLAB, viewTok, { workspaceId: workspace.id, review: { f1: "confirmed" } }),
    { sql, env: ENV },
  );
  assert.equal(patch.status, 403);
  const del = await handleTeamWorkspacesDelete(req("DELETE", `${WS}?id=${workspace.id}`, viewTok), { sql, env: ENV });
  assert.equal(del.status, 403);
  assert.equal((await listWorkspaces(sql, a.context)).length, 1);
});

test("analyst PATCH policy is 200; accepted-risk requires lead", async () => {
  const { sql } = await openSql();
  const a = await ownerSession(sql);
  await addMember(sql, a.context, { userKey: "ana", role: "analyst" });
  await addMember(sql, a.context, { userKey: "lea", role: "lead" });
  const created = await handleTeamWorkspacesPost(req("POST", WS, a.token, { name: "desk" }), { sql, env: ENV });
  const { workspace } = (await created.json()) as { workspace: { id: string } };
  const anaTok = await memberToken(sql, a.tenant.id, "ana");
  const leaTok = await memberToken(sql, a.tenant.id, "lea");
  const policy = await handleTeamCollabPatch(
    req("PATCH", COLLAB, anaTok, { workspaceId: workspace.id, policy: DEFAULT_POLICY, review: { f1: "confirmed" } }),
    { sql, env: ENV },
  );
  assert.equal(policy.status, 200);
  const denied = await handleTeamCollabPatch(
    req("PATCH", COLLAB, anaTok, { workspaceId: workspace.id, review: { f1: "accepted-risk" } }),
    { sql, env: ENV },
  );
  assert.equal(denied.status, 403);
  const allowed = await handleTeamCollabPatch(
    req("PATCH", COLLAB, leaTok, { workspaceId: workspace.id, review: { f1: "accepted-risk" } }),
    { sql, env: ENV },
  );
  assert.equal(allowed.status, 200);
  const body = (await allowed.json()) as { collab: { review: Record<string, string> } };
  assert.equal(body.collab.review.f1, "accepted-risk");
});

test("caller tenant_id on workspace/collab body is rejected", async () => {
  const { sql } = await openSql();
  const a = await ownerSession(sql);
  const ws = await handleTeamWorkspacesPost(
    req("POST", WS, a.token, { name: "desk", tenant_id: "spoof" }),
    { sql, env: ENV },
  );
  assert.equal(ws.status, 400);
  const created = await handleTeamWorkspacesPost(req("POST", WS, a.token, { name: "desk" }), { sql, env: ENV });
  const { workspace } = (await created.json()) as { workspace: { id: string } };
  const collab = await handleTeamCollabPatch(
    req("PATCH", COLLAB, a.token, { workspaceId: workspace.id, policy: DEFAULT_POLICY, tenantId: a.tenant.id }),
    { sql, env: ENV },
  );
  assert.equal(collab.status, 400);
  const spoofGet = await handleTeamCollabGet(
    req("GET", `${COLLAB}?workspaceId=${workspace.id}&tenant_id=${a.tenant.id}`, a.token),
    { sql, env: ENV },
  );
  assert.equal(spoofGet.status, 400);
  const spoofActor = await handleTeamCollabPatch(
    req("PATCH", COLLAB, a.token, { workspaceId: workspace.id, policy: DEFAULT_POLICY, actorUserKey: "eve" }),
    { sql, env: ENV },
  );
  assert.equal(spoofActor.status, 400);
});

test("PATCH collab rejects capture secrets; stored row unchanged", async () => {
  const { sql } = await openSql();
  const a = await ownerSession(sql);
  const created = await handleTeamWorkspacesPost(req("POST", WS, a.token, { name: "desk" }), { sql, env: ENV });
  const { workspace } = (await created.json()) as { workspace: { id: string } };
  await handleTeamCollabPatch(req("PATCH", COLLAB, a.token, { workspaceId: workspace.id, policy: DEFAULT_POLICY }), {
    sql,
    env: ENV,
  });
  const jwt = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJhIn0.";
  const raw = await handleTeamCollabPatch(
    req("PATCH", COLLAB, a.token, { workspaceId: workspace.id, reportDto: { ...DTO, aRaw: "GET /" } }),
    { sql, env: ENV },
  );
  assert.equal(raw.status, 400);
  const compact = await handleTeamCollabPatch(
    req("PATCH", COLLAB, a.token, {
      workspaceId: workspace.id,
      reportDto: { ...DTO, findings: [{ title: `Bearer ${jwt}` }] },
    }),
    { sql, env: ENV },
  );
  assert.equal(compact.status, 400);
  const stored = await getCollab(sql, a.context, workspace.id);
  assert.equal(stored?.reportDto, null);
  assert.equal(stored?.policy?.version, DEFAULT_POLICY.version);
});

test("GET collab returns Team projection; loot value is redacted", async () => {
  const { sql } = await openSql();
  const a = await ownerSession(sql);
  const created = await handleTeamWorkspacesPost(req("POST", WS, a.token, { name: "desk" }), { sql, env: ENV });
  const { workspace } = (await created.json()) as { workspace: { id: string } };
  const saved = await handleTeamCollabPatch(
    req("PATCH", COLLAB, a.token, {
      workspaceId: workspace.id,
      reportDto: {
        ...DTO,
        loot: [{ kind: "note", severity: "low", label: "pw", value: "supersecretpassword", where: "body", actor: "A" }],
        replays: [
          {
            id: "r1",
            title: "login",
            severity: "low",
            note: "n",
            curl: "curl http://lab.test/me",
            raw: "GET /me HTTP/1.1",
          },
        ],
      },
    }),
    { sql, env: ENV },
  );
  assert.equal(saved.status, 200);
  const got = await handleTeamCollabGet(req("GET", `${COLLAB}?workspaceId=${workspace.id}`, a.token), {
    sql,
    env: ENV,
  });
  assert.equal(got.status, 200);
  const body = (await got.json()) as {
    collab: {
      reportDto: { loot: Array<{ value: string }>; replays: Array<{ raw: string; curl: string }> };
      tenantId?: string;
    };
  };
  assert.equal(body.collab.reportDto.loot[0]?.value, "[redacted]");
  assert.equal(body.collab.reportDto.replays[0]?.raw, "[redacted]");
  assert.equal(body.collab.reportDto.replays[0]?.curl, "[redacted]");
  assert.equal("tenantId" in body.collab, false);
  const events = await listAudit(sql, a.context);
  assert.equal(
    events.some((e) => e.action === "collab.update" && e.targetId === workspace.id),
    true,
  );
});

test("GET /api/team/collab is session-bound; tenant_id/actor query rejected", async () => {
  const { sql } = await openSql();
  const a = await ownerSession(sql);
  const created = await handleTeamWorkspacesPost(req("POST", WS, a.token, { name: "desk" }), { sql, env: ENV });
  const { workspace } = (await created.json()) as { workspace: { id: string } };
  const empty = await handleTeamCollabGet(req("GET", `${COLLAB}?workspaceId=${workspace.id}`, a.token), {
    sql,
    env: ENV,
  });
  assert.equal(empty.status, 200);
  assert.deepEqual(await empty.json(), { collab: null });
  const anon = await handleTeamCollabGet(req("GET", `${COLLAB}?workspaceId=${workspace.id}`), { sql, env: ENV });
  assert.equal(anon.status, 401);
  const missing = await handleTeamCollabGet(req("GET", COLLAB, a.token), { sql, env: ENV });
  assert.equal(missing.status, 400);
  const unknown = await handleTeamCollabGet(req("GET", `${COLLAB}?workspaceId=missing-desk`, a.token), {
    sql,
    env: ENV,
  });
  assert.equal(unknown.status, 404);
  const session = await handleTeamSession(req("GET", "https://app.example/api/team/session", a.token), {
    sql,
    env: ENV,
  });
  const me = (await session.json()) as { role?: unknown };
  assert.equal("role" in me, false);
});

test("Bearer JWT is not a Team session; HTTP collab is 400", async () => {
  const { sql } = await openSql();
  const jwtReq = new Request(COLLAB, {
    method: "GET",
    headers: { authorization: "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.e30.sig" },
  });
  const jwt = await handleTeamCollabGet(jwtReq, { sql, env: ENV });
  assert.equal(jwt.status, 401);
  const a = await ownerSession(sql);
  const http = await handleTeamCollabGet(
    new Request("http://app.example/api/team/collab?workspaceId=x", { headers: { cookie: cookieHeader(a.token) } }),
    { sql, env: ENV },
  );
  assert.equal(http.status, 400);
  assert.deepEqual(await http.json(), { error: "oidc requires HTTPS" });
});

test("cross-origin collab mutation is 401", async () => {
  const { sql } = await openSql();
  const a = await ownerSession(sql);
  const created = await handleTeamWorkspacesPost(req("POST", WS, a.token, { name: "desk" }), { sql, env: ENV });
  const { workspace } = (await created.json()) as { workspace: { id: string } };
  const res = await handleTeamCollabPatch(
    req(
      "PATCH",
      COLLAB,
      a.token,
      { workspaceId: workspace.id, policy: DEFAULT_POLICY },
      "https://evil.example",
    ),
    { sql, env: ENV },
  );
  assert.equal(res.status, 401);
  const del = await handleTeamWorkspacesDelete(
    req("DELETE", `${WS}?id=${workspace.id}`, a.token, undefined, "https://evil.example"),
    { sql, env: ENV },
  );
  assert.equal(del.status, 401);
  assert.equal((await listWorkspaces(sql, a.context)).length, 1);
});
