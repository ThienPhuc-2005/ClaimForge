import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { PGlite } from "@electric-sql/pglite";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { unlockBootstrap } from "./context.ts";
import {
  TEAM_SESSION_COOKIE,
  clearTeamSessionCookie,
  readTeamSessionToken,
  serializeTeamSessionCookie,
} from "./cookie.ts";
import { loadTeamOidcConfig } from "./oidc-config.ts";
import { resetTeamJwksCache } from "./oidc-jwks.ts";
import { handleTeamOidcCallback, handleTeamOidcLogin, handleTeamOidcLogout, handleTeamSession } from "./oidc-http.ts";
import { consumeOidcPending, insertOidcPending } from "./oidc-pending.ts";
import { hashOidcState, newOidcLoginSecrets } from "./oidc-pkce.ts";
import { oidcUserKey } from "./oidc-user-key.ts";
import { bootstrapTenant } from "./repo.ts";
import {
  SESSION_ROTATE_AFTER_MS,
  SESSION_ROTATE_GRACE_MS,
  loadTeamSession,
  mintTeamSession,
  remainingSessionMaxAge,
  revokeTeamSession,
  rotateTeamSession,
} from "./session.ts";
import { wrapPglite } from "./sql.ts";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "../../..");
const LAB_SQL = readFileSync(join(root, "migrations/0002_lab_revoke.sql"), "utf8");
const TEAM_SQL = readFileSync(join(root, "migrations/0003_team_isolation.sql"), "utf8");
const OIDC_SQL = readFileSync(join(root, "migrations/0004_team_oidc_sessions.sql"), "utf8");
const BOOTSTRAP = "test-bootstrap-secret-1";
const ISS = "https://idp-session.example";
const SUB = "user-1";

function testEnv(over: Record<string, string | undefined> = {}): Record<string, string | undefined> {
  return {
    CLAIMFORGE_TEAM_OIDC_ISSUER: ISS,
    CLAIMFORGE_TEAM_OIDC_CLIENT_ID: "claimforge",
    CLAIMFORGE_TEAM_OIDC_CLIENT_SECRET: "confidential-client-secret-value",
    CLAIMFORGE_TEAM_OIDC_REDIRECT_URI: "https://app.example/api/team/oidc/callback",
    CLAIMFORGE_TEAM_OIDC_AUTHORIZATION_ENDPOINT: "https://idp-session.example/authorize",
    CLAIMFORGE_TEAM_OIDC_TOKEN_ENDPOINT: "https://idp-session.example/token",
    CLAIMFORGE_TEAM_OIDC_JWKS_URI: "https://idp-session.example/jwks",
    CLAIMFORGE_TEAM_OIDC_ALLOWED_HOSTS: "idp-session.example",
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

test("__Host- session cookie is Secure HttpOnly Path=/ SameSite=Strict without Domain", () => {
  const header = serializeTeamSessionCookie("tok", 60);
  assert.match(header, new RegExp(`^${TEAM_SESSION_COOKIE}=tok;`));
  assert.match(header, /Secure/);
  assert.match(header, /HttpOnly/);
  assert.match(header, /Path=\//);
  assert.match(header, /SameSite=Strict/);
  assert.doesNotMatch(header, /Domain=/);
  assert.equal(readTeamSessionToken(header), "tok");
  assert.equal(readTeamSessionToken(clearTeamSessionCookie()), null);
});

test("pending stores hashed state and encrypted verifier, consume is single-use", async () => {
  const { sql } = await openP12();
  const config = loadTeamOidcConfig(testEnv());
  const secrets = newOidcLoginSecrets();
  const now = new Date("2026-08-30T10:00:00.000Z");
  await insertOidcPending(sql, config, { ...secrets, slug: "acme", now });
  const stored = await sql.query<{ state_hash: string; verifier_ciphertext: string }>(
    "SELECT state_hash, verifier_ciphertext FROM team_oidc_pending",
  );
  assert.equal(stored[0]?.state_hash, hashOidcState(secrets.state));
  assert.notEqual(stored[0]?.state_hash, secrets.state);
  assert.equal((stored[0]?.verifier_ciphertext ?? "").includes(secrets.verifier), false);
  const pending = await consumeOidcPending(sql, config, secrets.state, now);
  assert.equal(pending.verifier, secrets.verifier);
  assert.equal(pending.nonce, secrets.nonce);
  await assert.rejects(() => consumeOidcPending(sql, config, secrets.state, now));
});

test("opaque session stores only the SHA-256 hash and is tenant-bound", async () => {
  const { sql } = await openP12();
  const a = await bootstrapTenant(sql, unlockBootstrap(BOOTSTRAP, BOOTSTRAP), {
    slug: "acme",
    name: "Acme",
    ownerUserKey: "alice",
  });
  const b = await bootstrapTenant(sql, unlockBootstrap(BOOTSTRAP, BOOTSTRAP), {
    slug: "beta",
    name: "Beta",
    ownerUserKey: "bob",
  });
  const now = new Date("2026-08-30T10:00:00.000Z");
  const minted = await mintTeamSession(sql, a.context, now);
  const rows = await sql.query<{ token_hash: string; tenant_id: string }>("SELECT token_hash, tenant_id FROM team_session");
  assert.equal(rows.length, 1);
  assert.notEqual(rows[0]?.token_hash, minted.token);
  assert.equal(JSON.stringify(rows).includes(minted.token), false);
  assert.equal(rows[0]?.tenant_id, a.tenant.id);
  const loaded = await loadTeamSession(sql, minted.token, now);
  assert.equal(loaded?.session.userKey, "alice");
  assert.equal(loaded?.session.tenantId, a.tenant.id);
  assert.equal(loaded?.context.tenantId, a.tenant.id);
  assert.equal(await loadTeamSession(sql, minted.token + "x", now), null);
  await revokeTeamSession(sql, minted.token, now);
  assert.equal(await loadTeamSession(sql, minted.token, now), null);
  const other = await mintTeamSession(sql, b.context, now);
  assert.equal((await loadTeamSession(sql, other.token, now))?.session.tenantId, b.tenant.id);
});

test("deleted member cannot use a previously minted session", async () => {
  const { sql } = await openP12();
  const a = await bootstrapTenant(sql, unlockBootstrap(BOOTSTRAP, BOOTSTRAP), {
    slug: "acme",
    name: "Acme",
    ownerUserKey: "alice",
  });
  await sql.query("INSERT INTO team_member (tenant_id, user_key, role) VALUES ($1, $2, $3)", [
    a.tenant.id,
    "carol",
    "analyst",
  ]);
  const { resolveTenantContext } = await import("./context.ts");
  const carol = await resolveTenantContext(sql, "carol", a.tenant.id);
  const now = new Date("2026-08-30T10:00:00.000Z");
  const minted = await mintTeamSession(sql, carol, now);
  await sql.query("DELETE FROM team_member WHERE tenant_id = $1 AND user_key = $2", [a.tenant.id, "carol"]);
  assert.equal(await loadTeamSession(sql, minted.token, now), null);
});

test("session rotation is atomic after 6 hours and keeps the original expiry", async () => {
  const { sql } = await openP12();
  const a = await bootstrapTenant(sql, unlockBootstrap(BOOTSTRAP, BOOTSTRAP), {
    slug: "acme",
    name: "Acme",
    ownerUserKey: "alice",
  });
  const t0 = new Date("2026-08-30T10:00:00.000Z");
  const minted = await mintTeamSession(sql, a.context, t0);
  const later = new Date(t0.getTime() + SESSION_ROTATE_AFTER_MS);
  const rotated = await rotateTeamSession(sql, minted.token, later);
  assert.ok(rotated);
  assert.notEqual(rotated.token, minted.token);
  assert.equal(rotated.session.expiresAt.toISOString(), minted.session.expiresAt.toISOString());
  assert.equal((await loadTeamSession(sql, minted.token, later))?.session.id, minted.session.id);
  assert.equal((await loadTeamSession(sql, rotated.token, later))?.session.id, minted.session.id);
  const afterGrace = new Date(later.getTime() + SESSION_ROTATE_GRACE_MS + 1);
  assert.equal(await loadTeamSession(sql, minted.token, afterGrace), null);
  assert.equal((await loadTeamSession(sql, rotated.token, afterGrace))?.session.id, minted.session.id);
  assert.equal(remainingSessionMaxAge(rotated.session, t0), 12 * 60 * 60);
});

test("concurrent rotation does not log out the losing request", async () => {
  const { sql } = await openP12();
  const a = await bootstrapTenant(sql, unlockBootstrap(BOOTSTRAP, BOOTSTRAP), {
    slug: "acme",
    name: "Acme",
    ownerUserKey: "alice",
  });
  const t0 = new Date("2026-08-30T10:00:00.000Z");
  const minted = await mintTeamSession(sql, a.context, t0);
  const later = new Date(t0.getTime() + SESSION_ROTATE_AFTER_MS);
  const [one, two] = await Promise.all([
    rotateTeamSession(sql, minted.token, later),
    rotateTeamSession(sql, minted.token, later),
  ]);
  assert.ok(one);
  assert.ok(two);
  assert.equal(one.session.id, minted.session.id);
  assert.equal(two.session.id, minted.session.id);
  assert.equal(one.session.expiresAt.toISOString(), minted.session.expiresAt.toISOString());
  assert.equal(two.session.expiresAt.toISOString(), minted.session.expiresAt.toISOString());
  assert.ok(await loadTeamSession(sql, one.token, later));
  assert.ok(await loadTeamSession(sql, two.token, later));
  assert.ok(await loadTeamSession(sql, minted.token, later));
  const afterGrace = new Date(later.getTime() + SESSION_ROTATE_GRACE_MS + 1);
  const winner = one.token === minted.token ? two.token : one.token;
  assert.ok(await loadTeamSession(sql, winner, afterGrace));
  if (winner !== minted.token) {
    assert.equal(await loadTeamSession(sql, minted.token, afterGrace), null);
  }
});

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

test("login requires HTTPS and a syntactically valid slug", async () => {
  const { sql } = await openP12();
  await bootstrapTenant(sql, unlockBootstrap(BOOTSTRAP, BOOTSTRAP), {
    slug: "acme",
    name: "Acme",
    ownerUserKey: oidcUserKey(ISS, SUB),
  });
  const config = loadTeamOidcConfig(testEnv());
  const http = await handleTeamOidcLogin(new Request("http://app.example/api/team/oidc/login?slug=acme"), {
    sql,
    config,
  });
  assert.equal(http.status, 400);
  assert.equal(http.headers.get("cache-control"), "no-store");
  const spoof = await handleTeamOidcLogin(
    new Request("http://app.example/api/team/oidc/login?slug=acme", { headers: { "x-forwarded-proto": "https" } }),
    { sql, config },
  );
  assert.equal(spoof.status, 400);
  const missing = await handleTeamOidcLogin(new Request("https://app.example/api/team/oidc/login"), { sql, config });
  assert.equal(missing.status, 404);
  const unknown = await handleTeamOidcLogin(new Request("https://app.example/api/team/oidc/login?slug=nope"), {
    sql,
    config,
  });
  const ok = await handleTeamOidcLogin(new Request("https://app.example/api/team/oidc/login?slug=acme"), { sql, config });
  assert.equal(unknown.status, 302);
  assert.equal(ok.status, 302);
  assert.equal(ok.headers.get("cache-control"), "no-store");
  assert.equal(ok.headers.get("pragma"), "no-cache");
  const loc = new URL(ok.headers.get("location") ?? "");
  const ghost = new URL(unknown.headers.get("location") ?? "");
  assert.equal(loc.origin + loc.pathname, "https://idp-session.example/authorize");
  assert.equal(ghost.origin + ghost.pathname, loc.origin + loc.pathname);
  assert.equal(loc.searchParams.get("code_challenge_method"), "S256");
  assert.doesNotMatch(loc.href, /client_secret|confidential-client/);
});

test("callback mints a tenant-bound session and unknown subjects are not provisioned", async () => {
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
  const login = await handleTeamOidcLogin(new Request("https://app.example/api/team/oidc/login?slug=acme"), {
    sql,
    config,
    now,
  });
  const loc = new URL(login.headers.get("location") ?? "");
  const state = loc.searchParams.get("state") ?? "";
  const nonce = loc.searchParams.get("nonce") ?? "";
  const idToken = await new SignJWT({ nonce, sub: SUB })
    .setProtectedHeader({ alg: "RS256", kid: "k1" })
    .setIssuer(ISS)
    .setAudience("claimforge")
    .setIssuedAt(now)
    .setExpirationTime(new Date(now.getTime() + 300_000))
    .sign(k1.privateKey);
  const fetchImpl = (async (input: RequestInfo | URL) => {
    const href = String(input);
    if (href.includes("/token")) return jsonResponse({ id_token: idToken, access_token: "drop-me" });
    return jsonResponse({ keys: [k1.jwk] });
  }) as typeof fetch;
  const cb = await handleTeamOidcCallback(
    new Request(`https://app.example/api/team/oidc/callback?code=abc&state=${state}`),
    { sql, config, fetchImpl, now },
  );
  assert.equal(cb.status, 302);
  assert.equal(cb.headers.get("cache-control"), "no-store");
  assert.equal(cb.headers.get("referrer-policy"), "no-referrer");
  const cookie = cb.headers.get("set-cookie") ?? "";
  assert.match(cookie, new RegExp(TEAM_SESSION_COOKIE));
  const token = readTeamSessionToken(cookie);
  assert.ok(token);
  const session = await handleTeamSession(
    new Request("https://app.example/api/team/session", { headers: { cookie } }),
    { sql, config, now },
  );
  assert.equal(session.status, 200);
  assert.equal(session.headers.get("cache-control"), "no-store");
  const body = (await session.json()) as { userKey: string; tenantId: string; tenants?: unknown };
  assert.equal(body.userKey, userKey);
  assert.equal("tenants" in body, false);

  const login2 = await handleTeamOidcLogin(new Request("https://app.example/api/team/oidc/login?slug=acme"), {
    sql,
    config,
    now,
  });
  const loc2 = new URL(login2.headers.get("location") ?? "");
  const state2 = loc2.searchParams.get("state") ?? "";
  const nonce2 = loc2.searchParams.get("nonce") ?? "";
  const strangerToken = await new SignJWT({ nonce: nonce2, sub: "stranger" })
    .setProtectedHeader({ alg: "RS256", kid: "k1" })
    .setIssuer(ISS)
    .setAudience("claimforge")
    .setIssuedAt(now)
    .setExpirationTime(new Date(now.getTime() + 300_000))
    .sign(k1.privateKey);
  const fetchStranger = (async (input: RequestInfo | URL) => {
    if (String(input).includes("/token")) return jsonResponse({ id_token: strangerToken });
    return jsonResponse({ keys: [k1.jwk] });
  }) as typeof fetch;
  const denied = await handleTeamOidcCallback(
    new Request(`https://app.example/api/team/oidc/callback?code=abc&state=${state2}`),
    { sql, config, fetchImpl: fetchStranger, now },
  );
  assert.equal(denied.status, 404);
  const members = await sql.query<{ n: string }>("SELECT COUNT(*)::text AS n FROM team_member");
  assert.equal(members[0]?.n, "2");

  const logout = await handleTeamOidcLogout(
    new Request("https://app.example/api/team/oidc/logout", { method: "POST", headers: { cookie } }),
    { sql, config, now },
  );
  assert.equal(logout.status, 200);
  assert.equal(logout.headers.get("cache-control"), "no-store");
  const after = await handleTeamSession(new Request("https://app.example/api/team/session", { headers: { cookie } }), {
    sql,
    config,
    now,
  });
  assert.equal(after.status, 401);
});
