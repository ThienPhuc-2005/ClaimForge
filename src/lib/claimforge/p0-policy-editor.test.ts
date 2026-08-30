import assert from "node:assert/strict";
import { test } from "node:test";
import { analyze } from "./analyze.ts";
import { demoActorA, demoActorB } from "./demo.ts";
import {
  applyPolicyEdit,
  bumpPolicyVersion,
  clonePolicy,
  DEFAULT_POLICY,
  diffFindingSets,
  isPrivilegeEscalation,
  isPrivilegedRole,
  parseRoleHierarchy,
  policyContentFingerprint,
  policyFingerprint,
  roleImplies,
  validatePolicyPatterns,
} from "./policy.ts";

function har(entries: object[]) {
  return JSON.stringify({ log: { version: "1.2", entries } });
}

function jwt(sub: string) {
  const header = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0";
  const payload = Buffer.from(JSON.stringify({ sub }), "utf8")
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
  return `${header}.${payload}.`;
}

function get(t: string, url: string, status: number, sub: string, body: object) {
  return {
    startedDateTime: t,
    request: {
      method: "GET",
      url,
      headers: [{ name: "Authorization", value: `Bearer ${jwt(sub)}` }],
    },
    response: { status, headers: [], content: { text: JSON.stringify(body) } },
  };
}

function confirmedBola(ws: ReturnType<typeof analyze>) {
  return ws.findings.filter((f) => f.confidence === "confirmed" && /BOLA|IDOR/i.test(f.title));
}

test("policy fingerprint changes when patterns change even if version is identical", () => {
  const a = clonePolicy(DEFAULT_POLICY);
  const b = clonePolicy(DEFAULT_POLICY);
  b.publicPathPatterns = [...b.publicPathPatterns, "invoices"];
  assert.equal(a.version, b.version);
  assert.notEqual(policyContentFingerprint(a), policyContentFingerprint(b));
  assert.notEqual(policyFingerprint(a), policyFingerprint(b));
});

test("applyPolicyEdit bumps version only when content changes", () => {
  const same = applyPolicyEdit(DEFAULT_POLICY, clonePolicy(DEFAULT_POLICY));
  assert.equal(same.version, DEFAULT_POLICY.version);
  const draft = clonePolicy(DEFAULT_POLICY);
  draft.publicPathPatterns = ["catalog", "invoices"];
  const next = applyPolicyEdit(DEFAULT_POLICY, draft);
  assert.equal(next.version, bumpPolicyVersion(DEFAULT_POLICY.version));
  assert.equal(bumpPolicyVersion("policy-1"), "policy-2");
});

test("marking invoices public demotes confirmed BOLA and changelog records it", () => {
  const a = har([
    get("2026-08-30T03:00:00.000Z", "https://shop.lab/api/invoices/5512", 200, "alice", {
      id: 5512,
      ownerId: "alice",
    }),
  ]);
  const b = har([
    get("2026-08-30T03:00:01.000Z", "https://shop.lab/api/invoices/5512", 200, "bob", {
      id: 5512,
      ownerId: "alice",
    }),
  ]);
  const before = analyze(a, b, "alice", "bob");
  assert.ok(confirmedBola(before).length >= 1);
  const policy = clonePolicy(DEFAULT_POLICY);
  policy.publicPathPatterns = ["invoices"];
  const after = analyze(a, b, "alice", "bob", applyPolicyEdit(DEFAULT_POLICY, policy));
  assert.equal(confirmedBola(after).length, 0);
  assert.notEqual(before.inputHash, after.inputHash);
  assert.notEqual(before.policyVersion, after.policyVersion);
  const delta = diffFindingSets(before.findings, after.findings);
  assert.ok(delta.some((d) => d.kind === "removed" && /BOLA|IDOR/i.test(d.title)));
});

test("custom tenantId ownership field can confirm BOLA", () => {
  const policy = clonePolicy(DEFAULT_POLICY);
  policy.trustedOwnershipFields = ["tenantid"];
  const a = har([
    get("2026-08-30T03:10:00.000Z", "https://shop.lab/api/invoices/99", 200, "alice", {
      id: 99,
      tenantId: "acme",
    }),
  ]);
  const b = har([
    get("2026-08-30T03:10:01.000Z", "https://shop.lab/api/invoices/99", 200, "bob", {
      id: 99,
      tenantId: "acme",
    }),
  ]);
  const ws = analyze(a, b, "acme", "other", applyPolicyEdit(DEFAULT_POLICY, policy));
  assert.ok(confirmedBola(ws).length >= 1);
});

test("invalid regex is reported and does not match as a public route", () => {
  const policy = clonePolicy(DEFAULT_POLICY);
  policy.publicPathPatterns = ["(unclosed"];
  const errors = validatePolicyPatterns(policy);
  assert.equal(errors.length, 1);
  assert.match(errors[0]!.pattern, /unclosed/);
  const a = har([
    get("2026-08-30T03:20:00.000Z", "https://shop.lab/api/invoices/5512", 200, "alice", {
      id: 5512,
      ownerId: "alice",
    }),
  ]);
  const b = har([
    get("2026-08-30T03:20:01.000Z", "https://shop.lab/api/invoices/5512", 200, "bob", {
      id: 5512,
      ownerId: "alice",
    }),
  ]);
  const ws = analyze(a, b, "alice", "bob", policy);
  assert.ok(confirmedBola(ws).length >= 1);
});

test("role hierarchy parse and imply", () => {
  const policy = clonePolicy(DEFAULT_POLICY);
  policy.roleHierarchy = parseRoleHierarchy("admin: user, viewer\nuser: viewer");
  assert.equal(roleImplies(policy, "admin", "viewer"), true);
  assert.equal(roleImplies(policy, "viewer", "admin"), false);
  assert.equal(roleImplies(policy, "admin", "admin"), true);
  assert.equal(isPrivilegedRole(policy, "admin"), true);
  assert.equal(isPrivilegedRole(policy, "user"), true);
  assert.equal(isPrivilegedRole(policy, "viewer"), false);
  assert.equal(isPrivilegeEscalation(policy, "user", "admin"), true);
  assert.equal(isPrivilegeEscalation(policy, "admin", "user"), false);
});

test("mass-assign that climbs declared hierarchy is Confirmed ROLE_ESCALATION", () => {
  const policy = clonePolicy(DEFAULT_POLICY);
  policy.roleHierarchy = parseRoleHierarchy("admin: user, viewer");
  const header = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0";
  const payload = Buffer.from(JSON.stringify({ sub: "bob", role: "user" }), "utf8")
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
  const token = `${header}.${payload}.`;
  const a = har([
    {
      startedDateTime: "2026-08-30T04:00:00.000Z",
      request: {
        method: "PATCH",
        url: "https://shop.lab/api/users/me",
        headers: [{ name: "Authorization", value: `Bearer ${token}` }],
        postData: { text: JSON.stringify({ role: "admin" }) },
      },
      response: {
        status: 200,
        headers: [],
        content: { text: JSON.stringify({ id: "bob", role: "admin" }) },
      },
    },
  ]);
  const ws = analyze(a, "", "alice", "bob", applyPolicyEdit(DEFAULT_POLICY, policy));
  const hit = ws.findings.find((f) => f.reasonCodes.includes("ROLE_ESCALATION"));
  assert.ok(hit);
  assert.equal(hit!.confidence, "confirmed");
  assert.notEqual(hit!.severity, "critical");
});

test("JWT privileged-role finding is skipped when the role is not a declared tree parent", () => {
  const policy = clonePolicy(DEFAULT_POLICY);
  policy.roleHierarchy = parseRoleHierarchy("lead: user");
  const header = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0";
  const payload = Buffer.from(JSON.stringify({ sub: "alice", role: "admin" }), "utf8")
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
  const token = `${header}.${payload}.`;
  const a = har([
    {
      startedDateTime: "2026-08-30T05:00:00.000Z",
      request: {
        method: "GET",
        url: "https://shop.lab/api/me",
        headers: [{ name: "Authorization", value: `Bearer ${token}` }],
      },
      response: { status: 200, headers: [], content: { text: JSON.stringify({ id: "alice" }) } },
    },
  ]);
  const skipped = analyze(a, "", "alice", "bob", applyPolicyEdit(DEFAULT_POLICY, policy));
  assert.ok(!skipped.findings.some((f) => f.reasonCodes.includes("JWT_PRIVILEGED_ROLE")));

  policy.roleHierarchy = parseRoleHierarchy("admin: user");
  const scored = analyze(a, "", "alice", "bob", applyPolicyEdit(DEFAULT_POLICY, policy));
  assert.ok(scored.findings.some((f) => f.reasonCodes.includes("JWT_PRIVILEGED_ROLE")));
});

test("empty hierarchy does not confirm mass-assign role write (demo regression)", () => {
  const ws = analyze(demoActorA(), demoActorB(), "alice", "bob");
  const mass = ws.findings.filter((f) => f.reasonCodes.includes("MASS_ASSIGN_HONORED"));
  assert.ok(mass.length >= 1);
  assert.ok(mass.every((f) => f.confidence === "observation"));
  assert.ok(mass.every((f) => !f.reasonCodes.includes("ROLE_ESCALATION")));
});

test("deny status 404 from policy is not success", () => {
  const policy = clonePolicy(DEFAULT_POLICY);
  policy.successStatuses = [200];
  policy.denyStatuses = [401, 403, 404];
  const a = har([
    get("2026-08-30T03:30:00.000Z", "https://shop.lab/api/invoices/1", 200, "alice", { id: 1, ownerId: "alice" }),
  ]);
  const b = har([
    get("2026-08-30T03:30:01.000Z", "https://shop.lab/api/invoices/1", 404, "bob", { error: "no" }),
  ]);
  const ws = analyze(a, b, "alice", "bob", policy);
  const row = ws.diffs.find((d) => d.template.includes("/invoices"));
  assert.equal(row?.verdict, "denied");
  assert.equal(confirmedBola(ws).length, 0);
});

test("lab demo still confirms BOLA under default policy after editor wiring", () => {
  const ws = analyze(demoActorA(), demoActorB(), "alice", "bob");
  assert.ok(confirmedBola(ws).length >= 1);
  assert.equal(ws.policy.version, DEFAULT_POLICY.version);
});
