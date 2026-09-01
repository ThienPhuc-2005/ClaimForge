import { rejectCallerAuditSpoof } from "./audit.ts";
import { rejectCallerTenantId } from "./context.ts";
import { requestIsHttps, readTeamSessionToken, serializeTeamSessionCookie } from "./cookie.ts";
import {
  TeamAuthError,
  TeamForbiddenError,
  TeamIsolationError,
  TeamNotFoundError,
  TeamPersistError,
  TeamValidationError,
} from "./errors.ts";
import { loadTeamOidcConfig } from "./oidc-config.ts";
import type { TeamHttpDeps } from "./oidc-http.ts";
import {
  createWorkspace,
  deleteWorkspace,
  getCollab,
  listWorkspaces,
  updateWorkspaceCollab,
} from "./repo.ts";
import { remainingSessionMaxAge, rotateTeamSession } from "./session.ts";
import { getTeamSql } from "./sql.ts";
import type { CollabWrite, TeamCollab, TeamSql, TeamWorkspace } from "./types.ts";

const AUTH_HEADERS: Record<string, string> = {
  "Cache-Control": "no-store",
  Pragma: "no-cache",
  "Referrer-Policy": "no-referrer",
};

function json(status: number, body: Record<string, unknown>, extra?: HeadersInit): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", ...AUTH_HEADERS, ...extra },
  });
}

function fail(err: unknown): Response {
  if (err instanceof TeamAuthError && err.message === "oidc requires HTTPS") {
    return json(400, { error: "oidc requires HTTPS" });
  }
  if (err instanceof TeamAuthError && err.message === "oidc is not configured") {
    return json(503, { error: "oidc is not configured" });
  }
  if (err instanceof TeamForbiddenError) {
    return json(403, { error: "forbidden" });
  }
  if (
    err instanceof TeamIsolationError ||
    err instanceof TeamValidationError ||
    err instanceof TeamPersistError
  ) {
    return json(400, { error: "invalid" });
  }
  if (err instanceof TeamNotFoundError) {
    return json(404, { error: "not found" });
  }
  if (err instanceof TeamAuthError) {
    return json(401, { error: "login failed" });
  }
  return json(401, { error: "login failed" });
}

function requireHttps(request: Request, env?: Record<string, string | undefined>): void {
  if (!requestIsHttps(request, env)) throw new TeamAuthError("oidc requires HTTPS");
}

function sameOrigin(request: Request): boolean {
  const origin = request.headers.get("origin");
  if (!origin) return true;
  try {
    return new URL(origin).origin === new URL(request.url).origin;
  } catch {
    return false;
  }
}

async function depsOrLoad(deps: TeamHttpDeps = {}): Promise<{ sql: TeamSql; now: Date }> {
  if (!deps.config && !deps.sql) loadTeamOidcConfig(deps.env);
  const sql = deps.sql ?? (await getTeamSql());
  return { sql, now: deps.now ?? new Date() };
}

async function authed(
  request: Request,
  deps: TeamHttpDeps,
): Promise<{
  sql: TeamSql;
  token: string;
  rotated: NonNullable<Awaited<ReturnType<typeof rotateTeamSession>>>;
}> {
  requireHttps(request, deps.env);
  const { sql, now } = await depsOrLoad(deps);
  const token = readTeamSessionToken(request.headers.get("cookie"));
  if (!token) throw new TeamAuthError("login failed");
  const rotated = await rotateTeamSession(sql, token, now);
  if (!rotated) throw new TeamAuthError("login failed");
  return { sql, token, rotated };
}

function withSession(
  res: Response,
  rotated: NonNullable<Awaited<ReturnType<typeof rotateTeamSession>>>,
  token: string,
): Response {
  if (rotated.token === token) return res;
  const headers = new Headers(res.headers);
  headers.set(
    "Set-Cookie",
    serializeTeamSessionCookie(rotated.token, remainingSessionMaxAge(rotated.session, new Date())),
  );
  return new Response(res.body, { status: res.status, headers });
}

async function readJsonObject(request: Request): Promise<Record<string, unknown>> {
  const raw = await request.text();
  if (!raw) return {};
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new TeamValidationError("body is invalid");
  }
  if (parsed == null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new TeamValidationError("body is invalid");
  }
  rejectCallerTenantId(parsed);
  rejectCallerAuditSpoof(parsed);
  return parsed as Record<string, unknown>;
}

function requestParams(request: Request): Record<string, string> {
  const params = Object.fromEntries(new URL(request.url).searchParams.entries());
  rejectCallerTenantId(params);
  rejectCallerAuditSpoof(params);
  return params;
}

function requireWorkspaceId(value: unknown): string {
  if (typeof value !== "string") throw new TeamValidationError("workspace id is required");
  const id = value.trim();
  if (!id || id.length > 128 || id.includes("\0")) {
    throw new TeamValidationError("workspace id is invalid");
  }
  return id;
}

function publicWorkspace(row: TeamWorkspace): {
  id: string;
  name: string;
  createdByUserKey: string;
  createdAt: string;
} {
  return {
    id: row.id,
    name: row.name,
    createdByUserKey: row.createdByUserKey,
    createdAt: row.createdAt,
  };
}

function publicCollab(row: TeamCollab): {
  workspaceId: string;
  policy: TeamCollab["policy"];
  review: TeamCollab["review"];
  reportDto: unknown;
  updatedByUserKey: string;
  updatedAt: string;
} {
  return {
    workspaceId: row.workspaceId,
    policy: row.policy,
    review: row.review,
    reportDto: row.reportDto,
    updatedByUserKey: row.updatedByUserKey,
    updatedAt: row.updatedAt,
  };
}

function collabWriteFromBody(body: Record<string, unknown>): { workspaceId: string; write: CollabWrite } {
  const workspaceId = requireWorkspaceId(body.workspaceId);
  const write: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(body)) {
    if (key === "workspaceId") continue;
    write[key] = value;
  }
  if (!("policy" in write) && !("review" in write) && !("reportDto" in write)) {
    throw new TeamValidationError("collab write is empty");
  }
  return { workspaceId, write: write as CollabWrite };
}

export async function handleTeamWorkspacesGet(request: Request, deps: TeamHttpDeps = {}): Promise<Response> {
  try {
    const { sql, token, rotated } = await authed(request, deps);
    requestParams(request);
    const workspaces = await listWorkspaces(sql, rotated.context);
    return withSession(json(200, { workspaces: workspaces.map(publicWorkspace) }), rotated, token);
  } catch (err) {
    return fail(err);
  }
}

export async function handleTeamWorkspacesPost(request: Request, deps: TeamHttpDeps = {}): Promise<Response> {
  try {
    if (!sameOrigin(request)) return json(401, { error: "login failed" });
    const { sql, token, rotated } = await authed(request, deps);
    const body = await readJsonObject(request);
    const workspace = await createWorkspace(sql, rotated.context, { name: body.name as string });
    return withSession(json(201, { workspace: publicWorkspace(workspace) }), rotated, token);
  } catch (err) {
    return fail(err);
  }
}

export async function handleTeamWorkspacesDelete(request: Request, deps: TeamHttpDeps = {}): Promise<Response> {
  try {
    if (!sameOrigin(request)) return json(401, { error: "login failed" });
    const { sql, token, rotated } = await authed(request, deps);
    const id = requireWorkspaceId(requestParams(request).id);
    await deleteWorkspace(sql, rotated.context, id);
    return withSession(json(200, { ok: true }), rotated, token);
  } catch (err) {
    return fail(err);
  }
}

export async function handleTeamCollabGet(request: Request, deps: TeamHttpDeps = {}): Promise<Response> {
  try {
    const { sql, token, rotated } = await authed(request, deps);
    const workspaceId = requireWorkspaceId(requestParams(request).workspaceId);
    const collab = await getCollab(sql, rotated.context, workspaceId);
    return withSession(json(200, { collab: collab ? publicCollab(collab) : null }), rotated, token);
  } catch (err) {
    return fail(err);
  }
}

export async function handleTeamCollabPatch(request: Request, deps: TeamHttpDeps = {}): Promise<Response> {
  try {
    if (!sameOrigin(request)) return json(401, { error: "login failed" });
    const { sql, token, rotated } = await authed(request, deps);
    const body = await readJsonObject(request);
    const { workspaceId, write } = collabWriteFromBody(body);
    const collab = await updateWorkspaceCollab(sql, rotated.context, workspaceId, write);
    return withSession(json(200, { collab: publicCollab(collab) }), rotated, token);
  } catch (err) {
    return fail(err);
  }
}
