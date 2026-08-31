import { rejectCallerTenantId, requireRole, requireUserKey } from "./context.ts";
import { requestIsHttps, readTeamSessionToken, serializeTeamSessionCookie } from "./cookie.ts";
import {
  TeamAuthError,
  TeamForbiddenError,
  TeamIsolationError,
  TeamNotFoundError,
  TeamValidationError,
} from "./errors.ts";
import { loadTeamOidcConfig } from "./oidc-config.ts";
import type { TeamHttpDeps } from "./oidc-http.ts";
import { addMember, listMembers, removeMember, updateMemberRole } from "./repo.ts";
import { remainingSessionMaxAge, rotateTeamSession } from "./session.ts";
import { getTeamSql } from "./sql.ts";
import type { TeamMember, TeamSql } from "./types.ts";

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
  if (err instanceof TeamIsolationError || err instanceof TeamValidationError) {
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

function publicMember(row: TeamMember): { userKey: string; role: string; createdAt: string } {
  return { userKey: row.userKey, role: row.role, createdAt: row.createdAt };
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

function withSession(res: Response, rotated: NonNullable<Awaited<ReturnType<typeof rotateTeamSession>>>, token: string): Response {
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
  return parsed as Record<string, unknown>;
}

export async function handleTeamMembersGet(request: Request, deps: TeamHttpDeps = {}): Promise<Response> {
  try {
    const { sql, token, rotated } = await authed(request, deps);
    const members = await listMembers(sql, rotated.context);
    const res = json(200, { members: members.map(publicMember) });
    return withSession(res, rotated, token);
  } catch (err) {
    return fail(err);
  }
}

export async function handleTeamMembersPost(request: Request, deps: TeamHttpDeps = {}): Promise<Response> {
  try {
    if (!sameOrigin(request)) return json(401, { error: "login failed" });
    const { sql, token, rotated } = await authed(request, deps);
    const body = await readJsonObject(request);
    const member = await addMember(sql, rotated.context, {
      userKey: requireUserKey(body.userKey),
      role: requireRole(body.role),
    });
    return withSession(json(201, { member: publicMember(member) }), rotated, token);
  } catch (err) {
    return fail(err);
  }
}

export async function handleTeamMembersPatch(request: Request, deps: TeamHttpDeps = {}): Promise<Response> {
  try {
    if (!sameOrigin(request)) return json(401, { error: "login failed" });
    const { sql, token, rotated } = await authed(request, deps);
    const body = await readJsonObject(request);
    const member = await updateMemberRole(sql, rotated.context, {
      userKey: requireUserKey(body.userKey),
      role: requireRole(body.role),
    });
    return withSession(json(200, { member: publicMember(member) }), rotated, token);
  } catch (err) {
    return fail(err);
  }
}

export async function handleTeamMembersDelete(request: Request, deps: TeamHttpDeps = {}): Promise<Response> {
  try {
    if (!sameOrigin(request)) return json(401, { error: "login failed" });
    const { sql, token, rotated } = await authed(request, deps);
    const userKey = new URL(request.url).searchParams.get("userKey");
    await removeMember(sql, rotated.context, requireUserKey(userKey));
    return withSession(json(200, { ok: true }), rotated, token);
  } catch (err) {
    return fail(err);
  }
}
