import assert from "node:assert/strict";
import { test } from "node:test";
import { SignJWT } from "jose";
import { handleLabRequest as lab, resetLabState } from "./engine.ts";
import { mintJwt as mint } from "../claimforge/jwt.ts";
import { LEAKED_LAB_HMAC } from "./secret.ts";

function req(path: string, init: RequestInit = {}, labMode?: "vulnerable" | "fixed") {
  const headers = new Headers(init.headers);
  if (labMode) headers.set("X-Lab-Mode", labMode);
  return new Request(`https://lab.local${path}`, { ...init, headers });
}

async function login(email: string) {
  const res = await lab(
    req("/api/lab/login", {
      method: "POST",
      body: JSON.stringify({ email, password: "demo" }),
      headers: { "content-type": "application/json" },
    }),
  );
  return (await res.json()) as { token: string };
}

test("BOLA: vulnerable allows bob to read alice invoice; fixed forbids", async () => {
  resetLabState();
  const alice = await login("alice@lab.test");
  const bob = await login("bob@lab.test");
  const vul = await lab(req("/api/lab/invoices/5512", { headers: { Authorization: `Bearer ${bob.token}` } }, "vulnerable"));
  assert.equal(vul.status, 200);
  const fix = await lab(req("/api/lab/invoices/5512", { headers: { Authorization: `Bearer ${bob.token}` } }, "fixed"));
  assert.equal(fix.status, 403);
  const own = await lab(req("/api/lab/invoices/5512", { headers: { Authorization: `Bearer ${alice.token}` } }, "fixed"));
  assert.equal(own.status, 200);
});

test("JWT: alg=none admin works only in vulnerable mode", async () => {
  resetLabState();
  const none = mint({ alg: "none", typ: "JWT" }, { sub: "alice", role: "admin" });
  const vul = await lab(req("/api/lab/admin/users", { headers: { Authorization: `Bearer ${none}` } }, "vulnerable"));
  assert.equal(vul.status, 200);
  const fix = await lab(req("/api/lab/admin/users", { headers: { Authorization: `Bearer ${none}` } }, "fixed"));
  assert.equal(fix.status, 401);
});

test("Fixed rejects HS256 admin forgery signed with leaked client secret", async () => {
  resetLabState();
  const leaked = new TextEncoder().encode(LEAKED_LAB_HMAC);
  const forged = await new SignJWT({ sub: "alice", role: "admin" })
    .setProtectedHeader({ alg: "HS256", typ: "JWT" })
    .setIssuedAt()
    .setExpirationTime("2h")
    .setJti("forged-admin")
    .sign(leaked);
  const fix = await lab(req("/api/lab/admin/users", { headers: { Authorization: `Bearer ${forged}` } }, "fixed"));
  assert.equal(fix.status, 401);
  const me = await lab(req("/api/lab/me", { headers: { Authorization: `Bearer ${forged}` } }, "fixed"));
  assert.equal(me.status, 401);
});

test("Fixed ignores role claim on a valid user token (role from account record)", async () => {
  resetLabState();
  const alice = await login("alice@lab.test");
  const admin = await lab(req("/api/lab/admin/users", { headers: { Authorization: `Bearer ${alice.token}` } }, "fixed"));
  assert.equal(admin.status, 403);
  const me = await lab(req("/api/lab/me", { headers: { Authorization: `Bearer ${alice.token}` } }, "fixed"));
  assert.equal(me.status, 200);
  const body = (await me.json()) as { role: string };
  assert.equal(body.role, "user");
});

test("logout: token still works when vulnerable, revoked when fixed", async () => {
  resetLabState();
  const { token } = await login("alice@lab.test");
  await lab(req("/api/lab/logout", { method: "POST", headers: { Authorization: `Bearer ${token}` } }, "vulnerable"));
  const still = await lab(req("/api/lab/me", { headers: { Authorization: `Bearer ${token}` } }, "vulnerable"));
  assert.equal(still.status, 200);
  await lab(req("/api/lab/logout", { method: "POST", headers: { Authorization: `Bearer ${token}` } }, "fixed"));
  const dead = await lab(req("/api/lab/me", { headers: { Authorization: `Bearer ${token}` } }, "fixed"));
  assert.equal(dead.status, 401);
});

test("Fixed logout jti cannot be reused after process-local cache is the revoke record", async () => {
  resetLabState();
  const { token } = await login("alice@lab.test");
  const logout = await lab(req("/api/lab/logout", { method: "POST", headers: { Authorization: `Bearer ${token}` } }, "fixed"));
  assert.equal(logout.status, 200);
  const again = await lab(req("/api/lab/me", { headers: { Authorization: `Bearer ${token}` } }, "fixed"));
  assert.equal(again.status, 401);
  const replayLogout = await lab(
    req("/api/lab/logout", { method: "POST", headers: { Authorization: `Bearer ${token}` } }, "fixed"),
  );
  assert.equal(replayLogout.status, 401);
});
