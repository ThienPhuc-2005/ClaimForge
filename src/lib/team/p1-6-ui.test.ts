import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { isMoreTab, isPrimaryTab, MORE_TAB_IDS, nextPrimaryTab } from "../claimforge/desk-nav.ts";
import { canAssignRole, hasCapability } from "./rbac.ts";
import {
  TEAM_LOOT_LOCAL_COPY,
  assignableRoles,
  canPushAcceptedRisk,
  collabWritePayload,
  isTeamSlug,
  liveRoleFromMembers,
  memberWritePayload,
  payloadHasTenantSpoof,
  publicSession,
  teamLoginPath,
  workspaceWritePayload,
} from "./ui.ts";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "../../..");

test("Team is a More inspect view, not a primary tab", () => {
  assert.equal(isMoreTab("team"), true);
  assert.equal(isPrimaryTab("team"), false);
  assert.equal(MORE_TAB_IDS.includes("team"), true);
  assert.equal(isPrimaryTab(nextPrimaryTab("", "team", "ArrowRight")), true);
  assert.equal(isMoreTab(nextPrimaryTab("", "team", "End")), false);
});

test("Team login path is slug-only; no tenant list or tenant_id", () => {
  assert.equal(isTeamSlug("acme"), true);
  assert.equal(isTeamSlug("A"), false);
  const path = teamLoginPath("Acme");
  assert.equal(path, "/api/team/oidc/login?slug=acme");
  assert.equal(path.includes("tenant_id"), false);
  assert.equal(path.includes("tenantId"), false);
  assert.equal(path.includes("/api/team/tenants"), false);
});

test("session JSON role is ignored; live role comes from members", () => {
  const session = publicSession({
    userKey: "alice",
    tenantId: "t1",
    role: "owner",
    tenants: [{ id: "t2" }],
  });
  assert.deepEqual(session, { userKey: "alice", tenantId: "t1" });
  assert.equal("role" in (session as object), false);
  assert.equal(liveRoleFromMembers("alice", [{ userKey: "alice", role: "viewer" }]), "viewer");
  assert.equal(liveRoleFromMembers("alice", [{ userKey: "bob", role: "owner" }]), null);
});

test("Team write payloads omit tenant_id and cannot assign owner", () => {
  const member = memberWritePayload("bob", "analyst");
  const ws = workspaceWritePayload("desk");
  const collab = collabWritePayload({ workspaceId: "w1", policy: { version: "policy-1" } });
  assert.equal(payloadHasTenantSpoof(member), false);
  assert.equal(payloadHasTenantSpoof(ws), false);
  assert.equal(payloadHasTenantSpoof(collab), false);
  assert.equal("tenantId" in member || "tenant_id" in member, false);
  assert.equal("tenantId" in collab || "tenant_id" in collab, false);
  assert.equal(canAssignRole("admin", "owner"), false);
  assert.equal(assignableRoles("admin").includes("owner"), false);
  assert.equal(hasCapability("viewer", "mutateWorkspace"), false);
  assert.equal(canPushAcceptedRisk("analyst", { f1: "accepted-risk" }), false);
  assert.equal(canPushAcceptedRisk("lead", { f1: "accepted-risk" }), true);
});

test("Team UI states loot/replay copy is local; does not import platform auth", () => {
  assert.match(TEAM_LOOT_LOCAL_COPY, /local analyst action/i);
  const view = readFileSync(join(root, "src/components/team-view.tsx"), "utf8");
  const client = readFileSync(join(root, "src/lib/team/client.ts"), "utf8");
  const ui = readFileSync(join(root, "src/lib/team/ui.ts"), "utf8");
  for (const src of [view, client, ui]) {
    assert.equal(src.includes("authMiddleware"), false);
    assert.equal(src.includes("requireUserId"), false);
    assert.equal(src.includes("@/lib/auth/server"), false);
    assert.equal(src.includes("better-auth"), false);
  }
  assert.equal(view.includes("TEAM_LOOT_LOCAL_COPY"), true);
  assert.equal(view.includes("/api/team/tenants"), false);
});

test("OIDC callback opens Team inspect without a tenant_id query", () => {
  const src = readFileSync(join(root, "src/lib/team/oidc-http.ts"), "utf8");
  assert.match(src, /redirect\("\/\?team=1"/);
  assert.equal(/redirect\("\/\?[^"]*tenant/i.test(src), false);
});
