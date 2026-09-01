import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { PGlite } from "@electric-sql/pglite";
import { DEFAULT_POLICY } from "../claimforge/policy.ts";
import { unlockBootstrap } from "./context.ts";
import { TeamForbiddenError, TeamNotFoundError } from "./errors.ts";
import { canAssignRole, hasCapability, reviewIncludesAcceptedRisk } from "./rbac.ts";
import {
  addMember,
  bootstrapTenant,
  createWorkspace,
  deleteWorkspace,
  getCollab,
  listMembers,
  listWorkspaces,
  removeMember,
  resolveTenantContext,
  updateMemberRole,
  updateWorkspaceCollab,
} from "./repo.ts";
import { wrapPglite } from "./sql.ts";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "../../..");
const LAB_SQL = readFileSync(join(root, "migrations/0002_lab_revoke.sql"), "utf8");
const TEAM_SQL = readFileSync(join(root, "migrations/0003_team_isolation.sql"), "utf8");
const SECRET = "test-bootstrap-secret-1";

async function openKernel() {
  const pg = new PGlite();
  await pg.waitReady;
  await pg.exec(LAB_SQL);
  await pg.exec(TEAM_SQL);
  return { pg, sql: wrapPglite(pg as never) };
}

function operator() {
  return unlockBootstrap(SECRET, SECRET);
}

test("viewer cannot mutate workspace, policy, or membership", async () => {
  const { sql } = await openKernel();
  const a = await bootstrapTenant(sql, operator(), { slug: "acme", name: "Acme", ownerUserKey: "alice" });
  await addMember(sql, a.context, { userKey: "view", role: "viewer" });
  const viewer = await resolveTenantContext(sql, "view", a.tenant.id);
  await assert.rejects(() => createWorkspace(sql, viewer, { name: "desk" }), TeamForbiddenError);
  const ws = await createWorkspace(sql, a.context, { name: "desk" });
  await assert.rejects(() => updateWorkspaceCollab(sql, viewer, ws.id, { policy: DEFAULT_POLICY }), TeamForbiddenError);
  await assert.rejects(() => deleteWorkspace(sql, viewer, ws.id), TeamForbiddenError);
  await assert.rejects(() => addMember(sql, viewer, { userKey: "eve", role: "analyst" }), TeamForbiddenError);
  assert.equal((await listMembers(sql, viewer)).some((m) => m.userKey === "view"), true);
  assert.equal((await listWorkspaces(sql, viewer)).length, 1);
  assert.equal(await getCollab(sql, viewer, ws.id), null);
});

test("accepted-risk requires lead or above", async () => {
  const { sql } = await openKernel();
  const a = await bootstrapTenant(sql, operator(), { slug: "acme", name: "Acme", ownerUserKey: "alice" });
  await addMember(sql, a.context, { userKey: "ana", role: "analyst" });
  await addMember(sql, a.context, { userKey: "lea", role: "lead" });
  const analyst = await resolveTenantContext(sql, "ana", a.tenant.id);
  const lead = await resolveTenantContext(sql, "lea", a.tenant.id);
  const ws = await createWorkspace(sql, analyst, { name: "desk" });
  await updateWorkspaceCollab(sql, analyst, ws.id, { policy: DEFAULT_POLICY, review: { f1: "confirmed" } });
  await assert.rejects(
    () => updateWorkspaceCollab(sql, analyst, ws.id, { review: { f1: "accepted-risk" } }),
    TeamForbiddenError,
  );
  const written = await updateWorkspaceCollab(sql, lead, ws.id, { review: { f1: "accepted-risk" } });
  assert.equal(written.review?.f1, "accepted-risk");
});

test("live member row role is authoritative, not the minted context snapshot", async () => {
  const { sql } = await openKernel();
  const a = await bootstrapTenant(sql, operator(), { slug: "acme", name: "Acme", ownerUserKey: "alice" });
  await addMember(sql, a.context, { userKey: "bob", role: "admin" });
  const bob = await resolveTenantContext(sql, "bob", a.tenant.id);
  assert.equal(bob.role, "admin");
  await sql.query("UPDATE team_member SET role = $3 WHERE tenant_id = $1 AND user_key = $2", [
    a.tenant.id,
    "bob",
    "viewer",
  ]);
  assert.equal(bob.role, "admin");
  await assert.rejects(() => addMember(sql, bob, { userKey: "mallory", role: "viewer" }), TeamForbiddenError);
  await assert.rejects(() => createWorkspace(sql, bob, { name: "nope" }), TeamForbiddenError);
  assert.equal((await listMembers(sql, a.context)).some((m) => m.userKey === "mallory"), false);
});

test("admin cannot assign owner or manage equal/higher ranks", async () => {
  const { sql } = await openKernel();
  const a = await bootstrapTenant(sql, operator(), { slug: "acme", name: "Acme", ownerUserKey: "alice" });
  await addMember(sql, a.context, { userKey: "ada", role: "admin" });
  await addMember(sql, a.context, { userKey: "ada2", role: "admin" });
  const admin = await resolveTenantContext(sql, "ada", a.tenant.id);
  await assert.rejects(() => addMember(sql, admin, { userKey: "root2", role: "owner" }), TeamForbiddenError);
  await assert.rejects(() => addMember(sql, admin, { userKey: "ada3", role: "admin" }), TeamForbiddenError);
  const lead = await addMember(sql, admin, { userKey: "lea", role: "lead" });
  assert.equal(lead.role, "lead");
  await assert.rejects(() => removeMember(sql, admin, "alice"), TeamForbiddenError);
  await assert.rejects(() => removeMember(sql, admin, "ada2"), TeamForbiddenError);
  await removeMember(sql, admin, "lea");
  assert.equal((await listMembers(sql, a.context)).some((m) => m.userKey === "lea"), false);
});

test("cannot remove or demote the last owner", async () => {
  const { sql } = await openKernel();
  const a = await bootstrapTenant(sql, operator(), { slug: "acme", name: "Acme", ownerUserKey: "alice" });
  await assert.rejects(() => removeMember(sql, a.context, "alice"), TeamForbiddenError);
  await assert.rejects(() => updateMemberRole(sql, a.context, { userKey: "alice", role: "admin" }), TeamForbiddenError);
  assert.equal((await listMembers(sql, a.context)).filter((m) => m.role === "owner").length, 1);
});

test("cross-tenant member HTTP authority is still not-found, not forbidden", async () => {
  const { sql } = await openKernel();
  const a = await bootstrapTenant(sql, operator(), { slug: "acme", name: "Acme", ownerUserKey: "alice" });
  const b = await bootstrapTenant(sql, operator(), { slug: "beta", name: "Beta", ownerUserKey: "bob" });
  await addMember(sql, a.context, { userKey: "carol", role: "analyst" });
  await assert.rejects(() => removeMember(sql, b.context, "carol"), TeamNotFoundError);
  await assert.rejects(() => updateMemberRole(sql, b.context, { userKey: "carol", role: "viewer" }), TeamNotFoundError);
});

test("capability matrix matches P1.3 ranks", () => {
  assert.equal(hasCapability("viewer", "mutateWorkspace"), false);
  assert.equal(hasCapability("analyst", "mutateWorkspace"), true);
  assert.equal(hasCapability("analyst", "acceptRisk"), false);
  assert.equal(hasCapability("lead", "acceptRisk"), true);
  assert.equal(hasCapability("lead", "manageMembers"), false);
  assert.equal(hasCapability("admin", "manageMembers"), true);
  assert.equal(canAssignRole("admin", "owner"), false);
  assert.equal(canAssignRole("owner", "owner"), false);
  assert.equal(canAssignRole("owner", "admin"), true);
  assert.equal(reviewIncludesAcceptedRisk({ f1: "confirmed" }), false);
  assert.equal(reviewIncludesAcceptedRisk({ f1: "accepted-risk" }), true);
});
