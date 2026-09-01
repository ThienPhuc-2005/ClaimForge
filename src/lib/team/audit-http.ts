import { listAudit, rejectCallerAuditSpoof } from "./audit.ts";
import { rejectCallerTenantId } from "./context.ts";
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
import { remainingSessionMaxAge, rotateTeamSession } from "./session.ts";
import { requestIsHttps, readTeamSessionToken, serializeTeamSessionCookie } from "./cookie.ts";
import { getTeamSql } from "./sql.ts";
import type { TeamAuditEvent } from "./audit.ts";
import type { TeamSql } from "./types.ts";

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

async function depsOrLoad(deps: TeamHttpDeps = {}): Promise<{ sql: TeamSql; now: Date }> {
  if (!deps.config && !deps.sql) loadTeamOidcConfig(deps.env);
  const sql = deps.sql ?? (await getTeamSql());
  return { sql, now: deps.now ?? new Date() };
}

function publicEvent(row: TeamAuditEvent): Record<string, unknown> {
  return {
    id: row.id,
    at: row.at,
    actorUserKey: row.actorUserKey,
    actorRole: row.actorRole,
    action: row.action,
    targetKind: row.targetKind,
    targetId: row.targetId,
    detail: row.detail,
  };
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

export async function handleTeamAuditGet(request: Request, deps: TeamHttpDeps = {}): Promise<Response> {
  try {
    const { sql, token, rotated } = await authed(request, deps);
    const params = Object.fromEntries(new URL(request.url).searchParams.entries());
    rejectCallerTenantId(params);
    rejectCallerAuditSpoof(params);
    const events = await listAudit(sql, rotated.context);
    const res = json(200, { events: events.map(publicEvent) });
    return withSession(res, rotated, token);
  } catch (err) {
    return fail(err);
  }
}
