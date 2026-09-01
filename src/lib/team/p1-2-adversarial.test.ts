import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { PGlite } from "@electric-sql/pglite";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { unlockBootstrap } from "./context.ts";
import { TEAM_SESSION_COOKIE, readTeamSessionToken, requestIsHttps } from "./cookie.ts";
import { loadTeamOidcConfig } from "./oidc-config.ts";
import {
  handleTeamOidcCallback,
  handleTeamOidcLogin,
  handleTeamOidcLogout,
  handleTeamSession,
} from "./oidc-http.ts";
import { resetTeamJwksCache } from "./oidc-jwks.ts";
import { consumeOidcPending, insertOidcPending, OIDC_PENDING_MAX_ROWS, OIDC_PENDING_TTL_MS } from "./oidc-pending.ts";
import { hashOidcState, newOidcLoginSecrets } from "./oidc-pkce.ts";
import { oidcUserKey } from "./oidc-user-key.ts";
import { bootstrapTenant } from "./repo.ts";
import { wrapPglite } from "./sql.ts";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "../../..");
const LAB_SQL = readFileSync(join(root, "migrations/0002_lab_revoke.sql"), "utf8");
const TEAM_SQL = readFileSync(join(root, "migrations/0003_team_isolation.sql"), "utf8");
const OIDC_SQL = readFileSync(join(root, "migrations/0004_team_oidc_sessions.sql"), "utf8");
const BOOTSTRAP = "test-bootstrap-secret-1";
const ISS = "https://idp-adv.example";
const SUB = "user-1";

function testEnv(over: Record<string, string | undefined> = {}): Record<string, string | undefined> {
  return {
    CLAIMFORGE_TEAM_OIDC_ISSUER: ISS,
    CLAIMFORGE_TEAM_OIDC_CLIENT_ID: "claimforge",
    CLAIMFORGE_TEAM_OIDC_CLIENT_SECRET: "confidential-client-secret-value",
    CLAIMFORGE_TEAM_OIDC_REDIRECT_URI: "https://app.example/api/team/oidc/callback",
    CLAIMFORGE_TEAM_OIDC_AUTHORIZATION_ENDPOINT: "https://idp-adv.example/authorize",
    CLAIMFORGE_TEAM_OIDC_TOKEN_ENDPOINT: "https://idp-adv.example/token",
    CLAIMFORGE_TEAM_OIDC_JWKS_URI: "https://idp-adv.example/jwks",
    CLAIMFORGE_TEAM_OIDC_ALLOWED_HOSTS: "idp-adv.example",
    CLAIMFORGE_TEAM_SEAL_KEY: "claimforge-team-seal-key-32bytes!",
    ...over,
  };
}

async function openP12() {
  const pg = new PGlite();
  await pg.waitReady;
  await pg.exec(LAB_SQL);
  await pg.exec(TEAM_SQL);
  await pg.exec(OIDC_SQL);
  return { pg, sql: wrapPglite(pg as never) };
}

function jsonResponse(body: unknown) {
  return new Response(JSON.stringify(body), { status: 200, headers: { "content-type": "application/json" } });
}

async function rsaKid(kid: string) {
  const pair = await generateKeyPair("RS256", { extractable: true });
  const jwk = await exportJWK(pair.publicKey);
  jwk.kid = kid;
  jwk.alg = "RS256";
  jwk.use = "sig";
  return { ...pair, jwk };
}

async function signId(
  key: Awaited<ReturnType<typeof rsaKid>>,
  claims: Record<string, unknown>,
  now: Date,
) {
  return new SignJWT(claims)
    .setProtectedHeader({ alg: "RS256", kid: "k1" })
    .setIssuer(ISS)
    .setAudience("claimforge")
    .setIssuedAt(now)
    .setExpirationTime(new Date(now.getTime() + 300_000))
    .sign(key.privateKey);
}

function fetchIdp(idToken: string, jwk: JsonWebKey) {
  return (async (input: RequestInfo | URL) => {
    if (String(input).includes("/token")) return jsonResponse({ id_token: idToken, access_token: "drop-me" });
    return jsonResponse({ keys: [jwk] });
  }) as typeof fetch;
}

test("0003 does not define OIDC or session tables", () => {
  assert.doesNotMatch(TEAM_SQL, /CREATE TABLE team_session|CREATE TABLE team_oidc_pending/i);
  assert.match(OIDC_SQL, /CREATE TABLE team_oidc_pending/);
  assert.match(OIDC_SQL, /CREATE TABLE team_session/);
  assert.match(OIDC_SQL, /ON DELETE CASCADE/);
});

test("Team OIDC sources do not import createRemoteJWKSet or platform auth", () => {
  const banned = [
    "createRemoteJWKSet",
    "authMiddleware",
    "requireUserId",
    "@/lib/auth/server",
    "@/lib/auth/middleware",
    "better-auth",
  ];
  const files = [
    ...readdirSync(here)
      .filter((f) => f.endsWith(".ts") && !f.endsWith(".test.ts") && !f.startsWith("p1-"))
      .map((f) => join(here, f)),
    join(root, "src/routes/api/team/oidc/login.ts"),
    join(root, "src/routes/api/team/oidc/callback.ts"),
    join(root, "src/routes/api/team/oidc/logout.ts"),
    join(root, "src/routes/api/team/session.ts"),
    join(root, "src/routes/api/team/members.ts"),
    join(root, "src/routes/api/team/audit.ts"),
    join(root, "src/routes/api/team/collab.ts"),
    join(root, "src/routes/api/team/workspaces.ts"),
    join(root, "scripts/team-bootstrap.mjs"),
  ];
  assert.ok(files.length >= 8);
  for (const file of files) {
    const src = readFileSync(file, "utf8");
    for (const token of banned) {
      assert.equal(src.includes(token), false, `${file} mentions ${token}`);
    }
  }
});

test("missing OIDC env fail-closes login with 503", async () => {
  const { sql } = await openP12();
  const res = await handleTeamOidcLogin(new Request("https://app.example/api/team/oidc/login?slug=acme"), {
    sql,
    env: {},
  });
  assert.equal(res.status, 503);
  assert.equal(res.headers.get("cache-control"), "no-store");
  assert.equal(res.headers.get("pragma"), "no-cache");
  assert.equal(((await res.json()) as { error: string }).error, "oidc is not configured");
});

test("X-Forwarded-Proto is ignored unless CLAIMFORGE_TEAM_TRUST_PROXY is set", async () => {
  const { sql } = await openP12();
  const config = loadTeamOidcConfig(testEnv());
  const httpReq = new Request("http://app.example/api/team/oidc/login?slug=acme", {
    headers: { "x-forwarded-proto": "https" },
  });
  assert.equal(requestIsHttps(httpReq), false);
  assert.equal(requestIsHttps(httpReq, {}), false);
  assert.equal(requestIsHttps(httpReq, { CLAIMFORGE_TEAM_TRUST_PROXY: "true" }), true);
  const denied = await handleTeamOidcLogin(httpReq, { sql, config });
  assert.equal(denied.status, 400);
  const allowed = await handleTeamOidcLogin(httpReq, {
    sql,
    config,
    env: { CLAIMFORGE_TEAM_TRUST_PROXY: "true" },
  });
  assert.equal(allowed.status, 302);
  assert.equal(requestIsHttps(new Request("https://app.example/api/team/oidc/login?slug=acme")), true);
});

test("valid unknown slug is indistinguishable from a live tenant at login", async () => {
  const { sql } = await openP12();
  await bootstrapTenant(sql, unlockBootstrap(BOOTSTRAP, BOOTSTRAP), {
    slug: "acme",
    name: "Acme",
    ownerUserKey: oidcUserKey(ISS, SUB),
  });
  const config = loadTeamOidcConfig(testEnv());
  const live = await handleTeamOidcLogin(new Request("https://app.example/api/team/oidc/login?slug=acme"), {
    sql,
    config,
  });
  const ghost = await handleTeamOidcLogin(new Request("https://app.example/api/team/oidc/login?slug=nope"), {
    sql,
    config,
  });
  assert.equal(live.status, ghost.status);
  assert.equal(live.status, 302);
  const liveLoc = new URL(live.headers.get("location") ?? "");
  const ghostLoc = new URL(ghost.headers.get("location") ?? "");
  assert.equal(liveLoc.origin + liveLoc.pathname, ghostLoc.origin + ghostLoc.pathname);
  const tenants = await sql.query<{ n: string }>("SELECT COUNT(*)::text AS n FROM team_tenant");
  assert.equal(tenants[0]?.n, "1");
});

test("pending rows are bounded and consumed rows are deleted", async () => {
  const { sql } = await openP12();
  const config = loadTeamOidcConfig(testEnv());
  const t0 = new Date("2026-08-30T10:00:00.000Z");
  const oldSecrets = newOidcLoginSecrets();
  await insertOidcPending(sql, config, { ...oldSecrets, slug: "oldxx", now: t0 });

  const later = new Date(t0.getTime() + 1_000);
  for (let i = 0; i < OIDC_PENDING_MAX_ROWS; i += 1) {
    const slug = `s${i.toString(36).padStart(4, "0")}`;
    const res = await handleTeamOidcLogin(new Request(`https://app.example/api/team/oidc/login?slug=${slug}`), {
      sql,
      config,
      now: later,
    });
    assert.equal(res.status, 302);
  }
  const full = await sql.query<{ n: string }>("SELECT COUNT(*)::text AS n FROM team_oidc_pending");
  assert.equal(Number(full[0]?.n), OIDC_PENDING_MAX_ROWS);
  const oldGone = await sql.query("SELECT 1 FROM team_oidc_pending WHERE state_hash = $1", [
    hashOidcState(oldSecrets.state),
  ]);
  assert.equal(oldGone.length, 0);
  await assert.rejects(() => consumeOidcPending(sql, config, oldSecrets.state, later));

  const live = await handleTeamOidcLogin(new Request("https://app.example/api/team/oidc/login?slug=acme"), {
    sql,
    config,
    now: later,
  });
  const ghost = await handleTeamOidcLogin(new Request("https://app.example/api/team/oidc/login?slug=nope"), {
    sql,
    config,
    now: later,
  });
  assert.equal(live.status, 302);
  assert.equal(ghost.status, 302);
  const capped = await sql.query<{ n: string }>("SELECT COUNT(*)::text AS n FROM team_oidc_pending");
  assert.equal(Number(capped[0]?.n), OIDC_PENDING_MAX_ROWS);

  const keep = newOidcLoginSecrets();
  await insertOidcPending(sql, config, { ...keep, slug: "keep", now: later });
  const pending = await consumeOidcPending(sql, config, keep.state, later);
  assert.equal(pending.slug, "keep");
  const afterConsume = await sql.query<{ n: string; hash?: string }>(
    "SELECT COUNT(*)::text AS n FROM team_oidc_pending",
  );
  assert.equal(Number(afterConsume[0]?.n), OIDC_PENDING_MAX_ROWS - 1);
  const consumedGone = await sql.query("SELECT 1 FROM team_oidc_pending WHERE state_hash = $1", [
    hashOidcState(keep.state),
  ]);
  assert.equal(consumedGone.length, 0);
  await assert.rejects(() => consumeOidcPending(sql, config, keep.state, later));

  const expSecrets = newOidcLoginSecrets();
  await insertOidcPending(sql, config, { ...expSecrets, slug: "expx", now: later });
  const afterTtl = new Date(later.getTime() + OIDC_PENDING_TTL_MS + 1);
  const next = newOidcLoginSecrets();
  await insertOidcPending(sql, config, { ...next, slug: "next", now: afterTtl });
  const expiredGone = await sql.query("SELECT 1 FROM team_oidc_pending WHERE state_hash = $1", [
    hashOidcState(expSecrets.state),
  ]);
  assert.equal(expiredGone.length, 0);
});

test("ID token tenant_id and role claims cannot switch tenant", async () => {
  resetTeamJwksCache();
  const { sql } = await openP12();
  const userKey = oidcUserKey(ISS, SUB);
  const acme = await bootstrapTenant(sql, unlockBootstrap(BOOTSTRAP, BOOTSTRAP), {
    slug: "acme",
    name: "Acme",
    ownerUserKey: userKey,
  });
  const beta = await bootstrapTenant(sql, unlockBootstrap(BOOTSTRAP, BOOTSTRAP), {
    slug: "beta",
    name: "Beta",
    ownerUserKey: oidcUserKey(ISS, "someone-else"),
  });
  const config = loadTeamOidcConfig(testEnv());
  const k1 = await rsaKid("k1");
  const now = new Date("2026-08-30T10:00:00.000Z");
  const login = await handleTeamOidcLogin(new Request("https://app.example/api/team/oidc/login?slug=acme"), {
    sql,
    config,
    now,
  });
  const loc = new URL(login.headers.get("location") ?? "");
  const idToken = await signId(
    k1,
    { nonce: loc.searchParams.get("nonce"), sub: SUB, tenant_id: beta.tenant.id, tenantId: beta.tenant.id, role: "owner" },
    now,
  );
  const cb = await handleTeamOidcCallback(
    new Request(`https://app.example/api/team/oidc/callback?code=abc&state=${loc.searchParams.get("state")}`),
    { sql, config, fetchImpl: fetchIdp(idToken, k1.jwk), now },
  );
  assert.equal(cb.status, 302);
  const cookie = cb.headers.get("set-cookie") ?? "";
  const session = await handleTeamSession(new Request("https://app.example/api/team/session", { headers: { cookie } }), {
    sql,
    config,
    now,
  });
  const body = (await session.json()) as { userKey: string; tenantId: string; role?: string; tenants?: unknown };
  assert.equal(session.status, 200);
  assert.equal(body.userKey, userKey);
  assert.equal(body.tenantId, acme.tenant.id);
  assert.notEqual(body.tenantId, beta.tenant.id);
  assert.equal("role" in body, false);
  assert.equal("tenants" in body, false);
});

test("login slug cannot bind a member of a different tenant", async () => {
  resetTeamJwksCache();
  const { sql } = await openP12();
  const userKey = oidcUserKey(ISS, SUB);
  await bootstrapTenant(sql, unlockBootstrap(BOOTSTRAP, BOOTSTRAP), {
    slug: "acme",
    name: "Acme",
    ownerUserKey: userKey,
  });
  await bootstrapTenant(sql, unlockBootstrap(BOOTSTRAP, BOOTSTRAP), {
    slug: "beta",
    name: "Beta",
    ownerUserKey: oidcUserKey(ISS, "someone-else"),
  });
  const config = loadTeamOidcConfig(testEnv());
  const k1 = await rsaKid("k1");
  const now = new Date("2026-08-30T10:00:00.000Z");
  const login = await handleTeamOidcLogin(new Request("https://app.example/api/team/oidc/login?slug=beta"), {
    sql,
    config,
    now,
  });
  const loc = new URL(login.headers.get("location") ?? "");
  const idToken = await signId(k1, { nonce: loc.searchParams.get("nonce"), sub: SUB }, now);
  const denied = await handleTeamOidcCallback(
    new Request(`https://app.example/api/team/oidc/callback?code=abc&state=${loc.searchParams.get("state")}`),
    { sql, config, fetchImpl: fetchIdp(idToken, k1.jwk), now },
  );
  assert.equal(denied.status, 404);
  const members = await sql.query<{ n: string }>("SELECT COUNT(*)::text AS n FROM team_member WHERE user_key = $1", [
    userKey,
  ]);
  assert.equal(members[0]?.n, "1");
  const sessions = await sql.query<{ n: string }>("SELECT COUNT(*)::text AS n FROM team_session");
  assert.equal(sessions[0]?.n, "0");
});

test("consumed OIDC state cannot be replayed", async () => {
  resetTeamJwksCache();
  const { sql } = await openP12();
  const userKey = oidcUserKey(ISS, SUB);
  await bootstrapTenant(sql, unlockBootstrap(BOOTSTRAP, BOOTSTRAP), {
    slug: "acme",
    name: "Acme",
    ownerUserKey: userKey,
  });
  const config = loadTeamOidcConfig(testEnv());
  const k1 = await rsaKid("k1");
  const now = new Date("2026-08-30T10:00:00.000Z");
  const login = await handleTeamOidcLogin(new Request("https://app.example/api/team/oidc/login?slug=acme"), {
    sql,
    config,
    now,
  });
  const loc = new URL(login.headers.get("location") ?? "");
  const state = loc.searchParams.get("state") ?? "";
  const idToken = await signId(k1, { nonce: loc.searchParams.get("nonce"), sub: SUB }, now);
  const fetchImpl = fetchIdp(idToken, k1.jwk);
  const first = await handleTeamOidcCallback(
    new Request(`https://app.example/api/team/oidc/callback?code=abc&state=${state}`),
    { sql, config, fetchImpl, now },
  );
  assert.equal(first.status, 302);
  assert.ok(readTeamSessionToken(first.headers.get("set-cookie")));
  const replay = await handleTeamOidcCallback(
    new Request(`https://app.example/api/team/oidc/callback?code=abc&state=${state}`),
    { sql, config, fetchImpl, now },
  );
  assert.equal(replay.status, 401);
  const sessions = await sql.query<{ n: string }>("SELECT COUNT(*)::text AS n FROM team_session");
  assert.equal(sessions[0]?.n, "1");
});

test("cross-origin logout is rejected and session stays live", async () => {
  resetTeamJwksCache();
  const { sql } = await openP12();
  await bootstrapTenant(sql, unlockBootstrap(BOOTSTRAP, BOOTSTRAP), {
    slug: "acme",
    name: "Acme",
    ownerUserKey: oidcUserKey(ISS, SUB),
  });
  const config = loadTeamOidcConfig(testEnv());
  const k1 = await rsaKid("k1");
  const now = new Date("2026-08-30T10:00:00.000Z");
  const login = await handleTeamOidcLogin(new Request("https://app.example/api/team/oidc/login?slug=acme"), {
    sql,
    config,
    now,
  });
  const loc = new URL(login.headers.get("location") ?? "");
  const idToken = await signId(k1, { nonce: loc.searchParams.get("nonce"), sub: SUB }, now);
  const cb = await handleTeamOidcCallback(
    new Request(`https://app.example/api/team/oidc/callback?code=abc&state=${loc.searchParams.get("state")}`),
    { sql, config, fetchImpl: fetchIdp(idToken, k1.jwk), now },
  );
  const cookie = cb.headers.get("set-cookie") ?? "";
  assert.match(cookie, new RegExp(TEAM_SESSION_COOKIE));
  const csrf = await handleTeamOidcLogout(
    new Request("https://app.example/api/team/oidc/logout", {
      method: "POST",
      headers: { cookie, origin: "https://evil.example" },
    }),
    { sql, config, now },
  );
  assert.equal(csrf.status, 401);
  const still = await handleTeamSession(new Request("https://app.example/api/team/session", { headers: { cookie } }), {
    sql,
    config,
    now,
  });
  assert.equal(still.status, 200);
});
