import assert from "node:assert/strict";
import { test } from "node:test";
import { actorRole, brokenFunctionLevelAuthz, isPrivilegedFunction } from "./bfla.ts";
import { DEFAULT_POLICY } from "./policy.ts";
import type { CapturedRequest, JwtToken } from "./types.ts";

function req(p: Partial<CapturedRequest>): CapturedRequest {
  return {
    id: "r",
    actor: "A",
    startedAt: 1,
    method: "GET",
    url: "https://shop.lab/x",
    origin: "https://shop.lab",
    path: "/x",
    template: "/x",
    query: {},
    requestHeaders: [],
    status: 200,
    statusText: "OK",
    responseHeaders: [],
    timeMs: 0,
    ...p,
  };
}

function jwt(actor: "A" | "B", role: string, sigStatus: JwtToken["sigStatus"]): JwtToken {
  return {
    actor,
    raw: "x.y.z",
    source: "auth",
    header: {},
    payload: { role },
    alg: "HS256",
    parts: 3,
    signature: "z",
    sigStatus,
    issues: [],
  };
}

test("isPrivilegedFunction matches admin + role-mutation routes, not normal ones", () => {
  assert.ok(isPrivilegedFunction("/admin/users"));
  assert.ok(isPrivilegedFunction("/api/management/config"));
  assert.ok(isPrivilegedFunction("/users/42/role"));
  assert.ok(isPrivilegedFunction("/roles"));
  assert.equal(isPrivilegedFunction("/invoices/42"), false);
  assert.equal(isPrivilegedFunction("/me"), false);
});

test("actorRole detects privilege across an actor's tokens", () => {
  const priv = actorRole([jwt("A", "user", "unsigned"), jwt("A", "admin", "verified")], "A", DEFAULT_POLICY);
  assert.equal(priv.privileged, true);
  assert.equal(priv.hasSignal, true);

  const nonPriv = actorRole([jwt("B", "user", "verified")], "B", DEFAULT_POLICY);
  assert.equal(nonPriv.privileged, false);
  assert.equal(nonPriv.verifiedNonPriv, true);
  assert.equal(nonPriv.label, "user");
});

test("BFLA suspicion: unverified non-priv actor 2xx on admin function, no enforcement", () => {
  const reqs = [req({ actor: "B", method: "GET", path: "/admin/users", template: "/admin/users", status: 200 })];
  const jwts = [jwt("B", "user", "unsigned")];
  const hits = brokenFunctionLevelAuthz(reqs, jwts, DEFAULT_POLICY);
  assert.equal(hits.length, 1);
  assert.equal(hits[0]!.confidence, "suspicion");
  assert.ok(hits[0]!.reasonCodes.includes("BFLA_PRIVILEGED_FUNCTION"));
  assert.ok(hits[0]!.reasonCodes.includes("MISSING_VERIFIED_ROLE"));
  assert.ok(hits[0]!.reasonCodes.includes("MISSING_FUNCTION_PRIVILEGE_PROOF"));
});

test("BFLA confirmed: verified non-priv role bypasses an enforced admin function", () => {
  const reqs = [
    req({ actor: "A", method: "DELETE", path: "/admin/users/9", template: "/admin/users/{id}", status: 403 }),
    req({ actor: "B", method: "DELETE", path: "/admin/users/9", template: "/admin/users/{id}", status: 200 }),
  ];
  const jwts = [jwt("A", "admin", "verified"), jwt("B", "user", "verified")];
  const hits = brokenFunctionLevelAuthz(reqs, jwts, DEFAULT_POLICY);
  assert.equal(hits.length, 1);
  assert.equal(hits[0]!.actor, "B");
  assert.equal(hits[0]!.confidence, "confirmed");
  assert.ok(hits[0]!.reasonCodes.includes("BFLA_ROLE_VERIFIED"));
  assert.ok(hits[0]!.reasonCodes.includes("BFLA_ENFORCEMENT_OBSERVED"));
});

test("BFLA does not fire for a privileged actor on their own admin route", () => {
  const reqs = [req({ actor: "A", method: "GET", path: "/admin/users", template: "/admin/users", status: 200 })];
  const jwts = [jwt("A", "admin", "verified")];
  assert.equal(brokenFunctionLevelAuthz(reqs, jwts, DEFAULT_POLICY).length, 0);
});

test("BFLA does not fire on a non-privileged route", () => {
  const reqs = [req({ actor: "B", method: "GET", path: "/invoices/1", template: "/invoices/{id}", status: 200 })];
  const jwts = [jwt("B", "user", "verified")];
  assert.equal(brokenFunctionLevelAuthz(reqs, jwts, DEFAULT_POLICY).length, 0);
});

test("BFLA needs a role or enforcement signal — unknown role + no deny stays silent", () => {
  const reqs = [req({ actor: "B", method: "GET", path: "/admin/panel", template: "/admin/panel", status: 200 })];
  assert.equal(brokenFunctionLevelAuthz(reqs, [], DEFAULT_POLICY).length, 0);
});

test("BFLA fires on enforcement contrast even when the role is unknown", () => {
  const reqs = [
    req({ actor: "A", method: "GET", path: "/admin/panel", template: "/admin/panel", status: 403 }),
    req({ actor: "B", method: "GET", path: "/admin/panel", template: "/admin/panel", status: 200 }),
  ];
  const hits = brokenFunctionLevelAuthz(reqs, [], DEFAULT_POLICY);
  assert.equal(hits.length, 1);
  assert.equal(hits[0]!.confidence, "suspicion");
  assert.ok(hits[0]!.reasonCodes.includes("BFLA_ENFORCEMENT_OBSERVED"));
});

// Regression: a 401 (unauthenticated) is NOT proof of function-level enforcement.
test("BFLA: an unauthenticated 401 then authenticated 200 is never Confirmed", () => {
  const reqs = [
    req({ actor: "B", method: "GET", path: "/api/feature-flags", template: "/api/feature-flags", status: 401 }),
    req({ actor: "B", method: "GET", path: "/api/feature-flags", template: "/api/feature-flags", status: 200 }),
  ];
  const jwts = [jwt("B", "user", "verified")];
  const hits = brokenFunctionLevelAuthz(reqs, jwts, DEFAULT_POLICY);
  // At most a suspicion (never a false Confirmed off a 401).
  assert.ok(hits.every((h) => h.confidence !== "confirmed"));
  assert.ok(hits.every((h) => !h.reasonCodes.includes("BFLA_ENFORCEMENT_OBSERVED")));
});

// Regression: is_admin:true is a privilege signal; the real admin must not be flagged.
test("BFLA: is_admin:true actor is treated as privileged", () => {
  const reqs = [
    req({ actor: "B", method: "DELETE", path: "/admin/users/9", template: "/admin/users/{id}", status: 403 }),
    req({ actor: "A", method: "DELETE", path: "/admin/users/9", template: "/admin/users/{id}", status: 200 }),
  ];
  const admin: JwtToken = { ...jwt("A", "", "verified"), payload: { is_admin: true } };
  const hits = brokenFunctionLevelAuthz(reqs, [admin, jwt("B", "user", "verified")], DEFAULT_POLICY);
  // A (is_admin) is expected; B was denied (not 2xx) so no hit at all.
  assert.equal(hits.filter((h) => h.actor === "A").length, 0);
});

// Regression: self-service routes are not privileged functions.
test("BFLA: /users/me/* self routes are excluded", () => {
  assert.equal(isPrivilegedFunction("/users/me/permissions"), false);
  assert.equal(isPrivilegedFunction("/me/settings"), false);
  assert.equal(isPrivilegedFunction("/manage-subscription"), false);
});

// Regression: verb-tampering — POST enforced (403), PUT bypasses (200) on same template.
test("BFLA: verb-tampering across the same template is caught", () => {
  const reqs = [
    req({ actor: "B", method: "POST", path: "/admin/promote/9", template: "/admin/promote/{id}", status: 403 }),
    req({ actor: "B", method: "PUT", path: "/admin/promote/9", template: "/admin/promote/{id}", status: 200 }),
  ];
  const hits = brokenFunctionLevelAuthz(reqs, [], DEFAULT_POLICY);
  assert.ok(hits.some((h) => h.method === "PUT" && h.reasonCodes.includes("BFLA_ENFORCEMENT_OBSERVED")));
});
