import { publicSession } from "./ui.ts";
import type { TeamRole } from "./types.ts";

export type TeamClientResult<T> =
  | { ok: true; status: number; data: T }
  | { ok: false; status: number; error: string };

async function readBody(res: Response): Promise<unknown> {
  const text = await res.text();
  if (!text) return null;
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return null;
  }
}

function errorOf(status: number, body: unknown): string {
  if (body && typeof body === "object" && "error" in body && typeof (body as { error: unknown }).error === "string") {
    return (body as { error: string }).error;
  }
  if (status === 401) return "login failed";
  if (status === 403) return "forbidden";
  if (status === 404) return "not found";
  if (status === 503) return "oidc is not configured";
  return "invalid";
}

async function teamRequest(path: string, init: RequestInit = {}, fetchImpl: typeof fetch = fetch): Promise<{ status: number; body: unknown }> {
  const headers = new Headers(init.headers);
  if (init.body && !headers.has("content-type")) headers.set("content-type", "application/json");
  headers.set("accept", "application/json");
  const res = await fetchImpl(path, { credentials: "same-origin", ...init, headers });
  return { status: res.status, body: await readBody(res) };
}

function wrap<T>(status: number, body: unknown, data: T | null): TeamClientResult<T> {
  if (status >= 200 && status < 300 && data != null) return { ok: true, status, data };
  if (status >= 200 && status < 300) return { ok: true, status, data: data as T };
  return { ok: false, status, error: errorOf(status, body) };
}

export type TeamSession = { userKey: string; tenantId: string };
export type TeamMemberRow = { userKey: string; role: TeamRole; createdAt: string };
export type TeamWorkspaceRow = { id: string; name: string; createdByUserKey: string; createdAt: string };
export type TeamCollabRow = {
  workspaceId: string;
  policy: unknown;
  review: Record<string, string> | null;
  reportDto: unknown;
  updatedByUserKey: string;
  updatedAt: string;
};
export type TeamAuditRow = {
  id: string;
  at: string;
  actorUserKey: string;
  actorRole: string;
  action: string;
  targetKind: string;
  targetId: string;
  detail: unknown;
};

export async function getTeamSession(fetchImpl?: typeof fetch): Promise<TeamClientResult<TeamSession | null>> {
  const { status, body } = await teamRequest("/api/team/session", { method: "GET" }, fetchImpl);
  if (status === 401 || status === 503) return { ok: true, status, data: null };
  const session = publicSession(body);
  return wrap(status, body, session);
}

export async function logoutTeam(fetchImpl?: typeof fetch): Promise<TeamClientResult<{ ok: true }>> {
  const { status, body } = await teamRequest("/api/team/oidc/logout", { method: "POST" }, fetchImpl);
  return wrap(status, body, status === 200 ? { ok: true as const } : null);
}

export async function listTeamMembers(fetchImpl?: typeof fetch): Promise<TeamClientResult<TeamMemberRow[]>> {
  const { status, body } = await teamRequest("/api/team/members", { method: "GET" }, fetchImpl);
  const members = Array.isArray((body as { members?: unknown })?.members)
    ? ((body as { members: TeamMemberRow[] }).members)
    : null;
  return wrap(status, body, members);
}

export async function addTeamMember(
  input: { userKey: string; role: TeamRole },
  fetchImpl?: typeof fetch,
): Promise<TeamClientResult<TeamMemberRow>> {
  const { status, body } = await teamRequest("/api/team/members", { method: "POST", body: JSON.stringify(input) }, fetchImpl);
  const member = (body as { member?: TeamMemberRow } | null)?.member ?? null;
  return wrap(status, body, member);
}

export async function patchTeamMember(
  input: { userKey: string; role: TeamRole },
  fetchImpl?: typeof fetch,
): Promise<TeamClientResult<TeamMemberRow>> {
  const { status, body } = await teamRequest("/api/team/members", { method: "PATCH", body: JSON.stringify(input) }, fetchImpl);
  const member = (body as { member?: TeamMemberRow } | null)?.member ?? null;
  return wrap(status, body, member);
}

export async function deleteTeamMember(userKey: string, fetchImpl?: typeof fetch): Promise<TeamClientResult<{ ok: true }>> {
  const params = new URLSearchParams({ userKey });
  const { status, body } = await teamRequest(`/api/team/members?${params.toString()}`, { method: "DELETE" }, fetchImpl);
  return wrap(status, body, status === 200 ? { ok: true as const } : null);
}

export async function listTeamWorkspaces(fetchImpl?: typeof fetch): Promise<TeamClientResult<TeamWorkspaceRow[]>> {
  const { status, body } = await teamRequest("/api/team/workspaces", { method: "GET" }, fetchImpl);
  const workspaces = Array.isArray((body as { workspaces?: unknown })?.workspaces)
    ? ((body as { workspaces: TeamWorkspaceRow[] }).workspaces)
    : null;
  return wrap(status, body, workspaces);
}

export async function createTeamWorkspace(name: string, fetchImpl?: typeof fetch): Promise<TeamClientResult<TeamWorkspaceRow>> {
  const { status, body } = await teamRequest("/api/team/workspaces", { method: "POST", body: JSON.stringify({ name }) }, fetchImpl);
  const workspace = (body as { workspace?: TeamWorkspaceRow } | null)?.workspace ?? null;
  return wrap(status, body, workspace);
}

export async function deleteTeamWorkspace(id: string, fetchImpl?: typeof fetch): Promise<TeamClientResult<{ ok: true }>> {
  const params = new URLSearchParams({ id });
  const { status, body } = await teamRequest(`/api/team/workspaces?${params.toString()}`, { method: "DELETE" }, fetchImpl);
  return wrap(status, body, status === 200 ? { ok: true as const } : null);
}

export async function getTeamCollab(workspaceId: string, fetchImpl?: typeof fetch): Promise<TeamClientResult<TeamCollabRow | null>> {
  const params = new URLSearchParams({ workspaceId });
  const { status, body } = await teamRequest(`/api/team/collab?${params.toString()}`, { method: "GET" }, fetchImpl);
  if (status === 200 && body && typeof body === "object" && "collab" in body) {
    return { ok: true, status, data: (body as { collab: TeamCollabRow | null }).collab };
  }
  return wrap(status, body, null);
}

export async function patchTeamCollab(
  payload: Record<string, unknown>,
  fetchImpl?: typeof fetch,
): Promise<TeamClientResult<TeamCollabRow>> {
  const { status, body } = await teamRequest("/api/team/collab", { method: "PATCH", body: JSON.stringify(payload) }, fetchImpl);
  const collab = (body as { collab?: TeamCollabRow } | null)?.collab ?? null;
  return wrap(status, body, collab);
}

export async function listTeamAudit(fetchImpl?: typeof fetch): Promise<TeamClientResult<TeamAuditRow[]>> {
  const { status, body } = await teamRequest("/api/team/audit", { method: "GET" }, fetchImpl);
  const events = Array.isArray((body as { events?: unknown })?.events)
    ? ((body as { events: TeamAuditRow[] }).events)
    : null;
  return wrap(status, body, events);
}
