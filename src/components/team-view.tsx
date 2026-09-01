import { useCallback, useEffect, useState } from "react";
import { toReportDTO } from "@/lib/claimforge/report.ts";
import { useForge } from "@/lib/claimforge/store";
import type { AnalysisPolicy } from "@/lib/claimforge/policy.ts";
import type { ReviewState } from "@/lib/claimforge/types.ts";
import {
  addTeamMember,
  createTeamWorkspace,
  deleteTeamMember,
  deleteTeamWorkspace,
  getTeamCollab,
  getTeamSession,
  listTeamAudit,
  listTeamMembers,
  listTeamWorkspaces,
  logoutTeam,
  patchTeamCollab,
  type TeamAuditRow,
  type TeamMemberRow,
  type TeamSession,
  type TeamWorkspaceRow,
} from "@/lib/team/client.ts";
import { hasCapability } from "@/lib/team/rbac.ts";
import type { TeamRole } from "@/lib/team/types.ts";
import {
  TEAM_LOOT_LOCAL_COPY,
  assignableRoles,
  canPushAcceptedRisk,
  collabWritePayload,
  isTeamSlug,
  liveRoleFromMembers,
  memberWritePayload,
  payloadHasTenantSpoof,
  teamLoginPath,
  workspaceWritePayload,
} from "@/lib/team/ui.ts";

export function TeamView() {
  const { policy, reviewByFingerprint, workspace, hydrateTeamCollab } = useForge();
  const [session, setSession] = useState<TeamSession | null>(null);
  const [members, setMembers] = useState<TeamMemberRow[]>([]);
  const [workspaces, setWorkspaces] = useState<TeamWorkspaceRow[]>([]);
  const [events, setEvents] = useState<TeamAuditRow[]>([]);
  const [selectedId, setSelectedId] = useState<string>("");
  const [slug, setSlug] = useState("");
  const [memberKey, setMemberKey] = useState("");
  const [memberRole, setMemberRole] = useState<TeamRole>("viewer");
  const [wsName, setWsName] = useState("");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [configured, setConfigured] = useState(true);

  const role = session ? liveRoleFromMembers(session.userKey, members) : null;
  const canMembers = role != null && hasCapability(role, "manageMembers");
  const canWrite = role != null && hasCapability(role, "mutateWorkspace");
  const roles = role ? assignableRoles(role) : [];

  const refresh = useCallback(async () => {
    const me = await getTeamSession();
    if (!me.ok) {
      setConfigured(me.status !== 503);
      setSession(null);
      return;
    }
    if (me.status === 503) {
      setConfigured(false);
      setSession(null);
      return;
    }
    setConfigured(true);
    if (!me.data) {
      setSession(null);
      setMembers([]);
      setWorkspaces([]);
      setEvents([]);
      return;
    }
    setSession(me.data);
    const [m, w, a] = await Promise.all([listTeamMembers(), listTeamWorkspaces(), listTeamAudit()]);
    if (m.ok && m.data) setMembers(m.data);
    if (w.ok && w.data) setWorkspaces(w.data);
    if (a.ok && a.data) setEvents(a.data);
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  async function run(label: string, fn: () => Promise<boolean>) {
    setBusy(true);
    setMessage(null);
    try {
      const ok = await fn();
      if (ok) {
        setMessage(label);
        await refresh();
      }
    } finally {
      setBusy(false);
    }
  }

  function fail(error: string) {
    setMessage(error);
    return false;
  }

  async function signIn() {
    if (!isTeamSlug(slug)) {
      setMessage("slug is invalid");
      return;
    }
    const path = teamLoginPath(slug);
    if (path.includes("tenant_id") || path.includes("tenantId")) {
      setMessage("invalid");
      return;
    }
    window.location.assign(path);
  }

  async function signOut() {
    await run("Signed out", async () => {
      const res = await logoutTeam();
      if (!res.ok) return fail(res.error);
      setSession(null);
      return true;
    });
  }

  async function addMember() {
    if (!canMembers || !role) return;
    await run("Member added", async () => {
      const payload = memberWritePayload(memberKey.trim(), memberRole);
      if (payloadHasTenantSpoof(payload)) return fail("invalid");
      const res = await addTeamMember(payload);
      if (!res.ok) return fail(res.error);
      setMemberKey("");
      return true;
    });
  }

  async function removeMember(userKey: string) {
    if (!canMembers) return;
    await run("Member removed", async () => {
      const res = await deleteTeamMember(userKey);
      if (!res.ok) return fail(res.error);
      return true;
    });
  }

  async function createWorkspace() {
    if (!canWrite) return;
    await run("Workspace created", async () => {
      const payload = workspaceWritePayload(wsName);
      if (payloadHasTenantSpoof(payload)) return fail("invalid");
      const res = await createTeamWorkspace(payload.name);
      if (!res.ok) return fail(res.error);
      setWsName("");
      if (res.data) setSelectedId(res.data.id);
      return true;
    });
  }

  async function removeWorkspace(id: string) {
    if (!canWrite) return;
    await run("Workspace deleted", async () => {
      const res = await deleteTeamWorkspace(id);
      if (!res.ok) return fail(res.error);
      if (selectedId === id) setSelectedId("");
      return true;
    });
  }

  async function pushDesk() {
    if (!canWrite || !selectedId) return;
    if (!canPushAcceptedRisk(role, reviewByFingerprint)) {
      setMessage("accepted-risk requires lead");
      return;
    }
    await run("Desk pushed", async () => {
      const payload = collabWritePayload({
        workspaceId: selectedId,
        policy,
        review: reviewByFingerprint,
        reportDto: toReportDTO(workspace),
      });
      if (payloadHasTenantSpoof(payload)) return fail("invalid");
      const res = await patchTeamCollab(payload);
      if (!res.ok) return fail(res.error);
      return true;
    });
  }

  async function pullDesk() {
    if (!selectedId) return;
    await run("Desk loaded", async () => {
      const res = await getTeamCollab(selectedId);
      if (!res.ok) return fail(res.error);
      if (!res.data) return fail("not found");
      const policyJson = res.data.policy as AnalysisPolicy | null;
      const review = (res.data.review ?? {}) as Record<string, ReviewState>;
      const ok = hydrateTeamCollab({ policy: policyJson, review });
      if (!ok) return fail("policy is invalid");
      return true;
    });
  }

  return (
    <div className="flex flex-col gap-4">
      <p className="text-xs leading-relaxed text-muted">
        Opt-in Team mode. Solo stays the default. Identity is your IdP session, not a tenant list. The first owner is an
        operator bootstrap — there is no public sign-up.
      </p>
      <p className="rounded-md border border-border bg-elevated px-3 py-2 text-xs leading-relaxed text-muted" role="note">
        {TEAM_LOOT_LOCAL_COPY}
      </p>
      {message ? (
        <p className="text-xs text-muted" role="status" aria-live="polite">
          {message}
        </p>
      ) : null}

      {!configured ? (
        <p className="text-sm text-muted">Team is not configured on this instance.</p>
      ) : !session ? (
        <section className="flex flex-col gap-2" aria-label="Team sign-in">
          <label className="text-xs text-muted">
            Tenant slug
            <input
              className="mt-1 h-11 w-full max-w-xs rounded-md border border-border bg-elevated px-2 font-mono text-sm text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
              value={slug}
              onChange={(e) => setSlug(e.target.value)}
              autoComplete="off"
              spellCheck={false}
              aria-label="Tenant slug"
            />
          </label>
          <button
            type="button"
            className="h-11 max-w-xs rounded-md bg-accent px-4 text-sm font-medium text-accent-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent disabled:opacity-50"
            disabled={busy || !isTeamSlug(slug)}
            onClick={() => void signIn()}
          >
            Sign in
          </button>
        </section>
      ) : (
        <>
          <section className="rounded-md border border-border bg-elevated p-3" aria-label="Team session">
            <p className="font-mono text-xs text-subtle">
              {session.userKey}
              {role ? ` · ${role}` : ""}
            </p>
            <p className="mt-1 font-mono text-xs text-muted">tenant {session.tenantId}</p>
            <p className="mt-2 text-xs text-subtle">Role comes from the live member list, not the session JSON.</p>
            <button
              type="button"
              className="mt-2 h-11 rounded-md border border-border px-4 text-sm text-fg hover:bg-surface focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
              onClick={() => void signOut()}
              disabled={busy}
            >
              Sign out
            </button>
          </section>

          <section className="flex flex-col gap-2" aria-label="Team members">
            <h3 className="text-sm font-semibold">Members</h3>
            <ul className="divide-y divide-border rounded-md border border-border">
              {members.map((m) => (
                <li key={m.userKey} className="flex items-center justify-between gap-2 px-3 py-2 text-sm">
                  <span className="font-mono text-xs">
                    {m.userKey} · {m.role}
                  </span>
                  {canMembers && m.userKey !== session.userKey ? (
                    <button
                      type="button"
                      className="h-11 rounded-md px-3 text-xs text-danger hover:bg-surface focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
                      onClick={() => void removeMember(m.userKey)}
                      disabled={busy}
                    >
                      Remove
                    </button>
                  ) : null}
                </li>
              ))}
            </ul>
            {canMembers ? (
              <div className="flex flex-wrap items-end gap-2">
                <label className="text-xs text-muted">
                  User key
                  <input
                    className="mt-1 h-11 w-56 rounded-md border border-border bg-elevated px-2 font-mono text-sm text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
                    value={memberKey}
                    onChange={(e) => setMemberKey(e.target.value)}
                    aria-label="New member user key"
                  />
                </label>
                <label className="text-xs text-muted">
                  Role
                  <select
                    className="mt-1 h-11 rounded-md border border-border bg-elevated px-2 text-sm text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
                    value={memberRole}
                    onChange={(e) => setMemberRole(e.target.value as TeamRole)}
                    aria-label="New member role"
                  >
                    {roles.map((r) => (
                      <option key={r} value={r}>
                        {r}
                      </option>
                    ))}
                  </select>
                </label>
                <button
                  type="button"
                  className="h-11 rounded-md bg-accent px-4 text-sm font-medium text-accent-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent disabled:opacity-50"
                  disabled={busy || !memberKey.trim() || !roles.includes(memberRole)}
                  onClick={() => void addMember()}
                >
                  Add member
                </button>
              </div>
            ) : (
              <p className="text-xs text-subtle">Member changes require admin.</p>
            )}
          </section>

          <section className="flex flex-col gap-2" aria-label="Team workspaces">
            <h3 className="text-sm font-semibold">Workspaces</h3>
            <ul className="divide-y divide-border rounded-md border border-border">
              {workspaces.map((w) => (
                <li key={w.id} className="flex items-center gap-2 px-3 py-2 text-sm">
                  <label className="flex min-h-11 flex-1 items-center gap-2">
                    <input
                      type="radio"
                      name="team-workspace"
                      checked={selectedId === w.id}
                      onChange={() => setSelectedId(w.id)}
                      aria-label={`Select workspace ${w.name}`}
                    />
                    <span>{w.name}</span>
                  </label>
                  {canWrite ? (
                    <button
                      type="button"
                      className="h-11 rounded-md px-3 text-xs text-danger hover:bg-surface focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
                      onClick={() => void removeWorkspace(w.id)}
                      disabled={busy}
                    >
                      Delete
                    </button>
                  ) : null}
                </li>
              ))}
            </ul>
            {canWrite ? (
              <div className="flex flex-wrap items-end gap-2">
                <label className="text-xs text-muted">
                  Name
                  <input
                    className="mt-1 h-11 w-56 rounded-md border border-border bg-elevated px-2 text-sm text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
                    value={wsName}
                    onChange={(e) => setWsName(e.target.value)}
                    aria-label="New workspace name"
                  />
                </label>
                <button
                  type="button"
                  className="h-11 rounded-md bg-accent px-4 text-sm font-medium text-accent-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent disabled:opacity-50"
                  disabled={busy || !wsName.trim()}
                  onClick={() => void createWorkspace()}
                >
                  Create workspace
                </button>
              </div>
            ) : (
              <p className="text-xs text-subtle">Workspace writes require analyst.</p>
            )}
            <div className="flex flex-wrap gap-2">
              <button
                type="button"
                className="h-11 rounded-md border border-border px-4 text-sm text-fg hover:bg-elevated focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent disabled:opacity-50"
                disabled={busy || !selectedId || !canWrite}
                onClick={() => void pushDesk()}
              >
                Push desk to workspace
              </button>
              <button
                type="button"
                className="h-11 rounded-md border border-border px-4 text-sm text-fg hover:bg-elevated focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent disabled:opacity-50"
                disabled={busy || !selectedId}
                onClick={() => void pullDesk()}
              >
                Load policy and review
              </button>
            </div>
          </section>

          <section className="flex flex-col gap-2" aria-label="Team audit">
            <h3 className="text-sm font-semibold">Audit</h3>
            <ul className="max-h-64 overflow-auto rounded-md border border-border font-mono text-xs">
              {events.map((e) => (
                <li key={e.id} className="border-b border-border px-3 py-2 text-muted">
                  {e.at} · {e.actorUserKey} ({e.actorRole}) · {e.action} · {e.targetKind}/{e.targetId}
                </li>
              ))}
              {events.length === 0 ? <li className="px-3 py-2 text-subtle">No events.</li> : null}
            </ul>
          </section>
        </>
      )}
    </div>
  );
}
