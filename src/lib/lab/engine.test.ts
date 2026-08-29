import assert from "node:assert/strict";
import { test } from "node:test";
import { handleLabRequest as lab, resetLabState } from "./engine.ts";
import { mintJwt as mint } from "../claimforge/jwt.ts";

function req(path: string, init: RequestInit = {}, labMode?: "vulnerable" | "fixed") {
  const headers = new Headers(init.headers);
  if (labMode) headers.set("X-Lab-Mode", labMode);
  return new Request(`https://lab.local${path}`, { ...init, headers });
}

test("BOLA: vulnerable allows bob to read alice invoice; fixed forbids", async () => {
  resetLabState();
  const alice = (await (
    await lab(
      req("/api/lab/login", {
        method: "POST",
        body: JSON.stringify({ email: "alice@lab.test", password: "demo" }),
        headers: { "content-type": "application/json" },
      }),
    )
  ).json()) as { token: string };
  const bob = (await (
    await lab(
      req("/api/lab/login", {
        method: "POST",
        body: JSON.stringify({ email: "bob@lab.test", password: "demo" }),
        headers: { "content-type": "application/json" },
      }),
    )
  ).json()) as { token: string };
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

test("logout: token still works when vulnerable, revoked when fixed", async () => {
  resetLabState();
  const login = await lab(
    req("/api/lab/login", {
      method: "POST",
      body: JSON.stringify({ email: "alice@lab.test", password: "demo" }),
      headers: { "content-type": "application/json" },
    }),
  );
  const { token } = (await login.json()) as { token: string };
  await lab(req("/api/lab/logout", { method: "POST", headers: { Authorization: `Bearer ${token}` } }, "vulnerable"));
  const still = await lab(req("/api/lab/me", { headers: { Authorization: `Bearer ${token}` } }, "vulnerable"));
  assert.equal(still.status, 200);
  await lab(req("/api/lab/logout", { method: "POST", headers: { Authorization: `Bearer ${token}` } }, "fixed"));
  const dead = await lab(req("/api/lab/me", { headers: { Authorization: `Bearer ${token}` } }, "fixed"));
  assert.equal(dead.status, 401);
});
