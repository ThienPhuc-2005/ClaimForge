import { requireSlug, resolveTenantContextBySlug } from "./context.ts";
import {
  clearTeamSessionCookie,
  readTeamSessionToken,
  requestIsHttps,
  serializeTeamSessionCookie,
} from "./cookie.ts";
import { TeamAuthError, TeamNotFoundError, TeamValidationError } from "./errors.ts";
import { loadTeamOidcConfig, type TeamOidcConfig } from "./oidc-config.ts";
import { verifyTeamIdToken } from "./oidc-id-token.ts";
import { newOidcLoginSecrets } from "./oidc-pkce.ts";
import { consumeOidcPending, insertOidcPending } from "./oidc-pending.ts";
import { exchangeAuthorizationCode } from "./oidc-token.ts";
import { oidcUserKey } from "./oidc-user-key.ts";
import {
  mintTeamSession,
  remainingSessionMaxAge,
  revokeTeamSession,
  rotateTeamSession,
} from "./session.ts";
import { getTeamSql } from "./sql.ts";
import type { TeamSql } from "./types.ts";

export type TeamHttpDeps = {
  sql?: TeamSql;
  config?: TeamOidcConfig;
  fetchImpl?: typeof fetch;
  now?: Date;
  env?: Record<string, string | undefined>;
};

function json(status: number, body: Record<string, unknown>, extra?: HeadersInit): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", ...extra },
  });
}

function fail(err: unknown): Response {
  if (err instanceof TeamAuthError && err.message === "oidc is not configured") {
    return json(503, { error: "oidc is not configured" });
  }
  if (err instanceof TeamAuthError && err.message === "oidc requires HTTPS") {
    return json(400, { error: "oidc requires HTTPS" });
  }
  if (err instanceof TeamNotFoundError || err instanceof TeamValidationError) {
    return json(404, { error: "not found" });
  }
  if (err instanceof TeamAuthError) {
    return json(401, { error: "login failed" });
  }
  return json(401, { error: "login failed" });
}

function requireHttps(request: Request): void {
  if (!requestIsHttps(request)) throw new TeamAuthError("oidc requires HTTPS");
}

async function depsOrLoad(deps: TeamHttpDeps = {}): Promise<{ sql: TeamSql; config: TeamOidcConfig; now: Date }> {
  const config = deps.config ?? loadTeamOidcConfig(deps.env);
  const sql = deps.sql ?? (await getTeamSql());
  return { sql, config, now: deps.now ?? new Date() };
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

export function authorizationRedirectUrl(
  config: TeamOidcConfig,
  input: { state: string; nonce: string; challenge: string },
): string {
  const url = new URL(config.authorizationEndpoint);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("client_id", config.clientId);
  url.searchParams.set("redirect_uri", config.redirectUri);
  url.searchParams.set("scope", "openid");
  url.searchParams.set("state", input.state);
  url.searchParams.set("nonce", input.nonce);
  url.searchParams.set("code_challenge", input.challenge);
  url.searchParams.set("code_challenge_method", "S256");
  return url.href;
}

export async function handleTeamOidcLogin(request: Request, deps: TeamHttpDeps = {}): Promise<Response> {
  try {
    requireHttps(request);
    const { sql, config, now } = await depsOrLoad(deps);
    const slug = new URL(request.url).searchParams.get("slug");
    if (!slug) throw new TeamValidationError("slug is required");
    const tenantSlug = requireSlug(slug);
    const tenants = await sql.query<{ id: string }>("SELECT id FROM team_tenant WHERE slug = $1", [tenantSlug]);
    if (!tenants[0]) throw new TeamNotFoundError("not found");
    const secrets = newOidcLoginSecrets();
    await insertOidcPending(sql, config, {
      state: secrets.state,
      nonce: secrets.nonce,
      verifier: secrets.verifier,
      challenge: secrets.challenge,
      slug: tenantSlug,
      now,
    });
    return new Response(null, {
      status: 302,
      headers: { Location: authorizationRedirectUrl(config, secrets) },
    });
  } catch (err) {
    return fail(err);
  }
}

export async function handleTeamOidcCallback(request: Request, deps: TeamHttpDeps = {}): Promise<Response> {
  try {
    requireHttps(request);
    const { sql, config, now } = await depsOrLoad(deps);
    const url = new URL(request.url);
    const code = url.searchParams.get("code") ?? "";
    const state = url.searchParams.get("state") ?? "";
    const pending = await consumeOidcPending(sql, config, state, now);
    const { idToken } = await exchangeAuthorizationCode(config, {
      code,
      codeVerifier: pending.verifier,
      fetchImpl: deps.fetchImpl,
    });
    const claims = await verifyTeamIdToken(idToken, {
      config,
      nonce: pending.nonce,
      fetchImpl: deps.fetchImpl,
      now,
    });
    const userKey = oidcUserKey(claims.iss, claims.sub);
    const context = await resolveTenantContextBySlug(sql, userKey, pending.slug);
    const minted = await mintTeamSession(sql, context, now);
    return new Response(null, {
      status: 302,
      headers: {
        Location: "/",
        "Set-Cookie": serializeTeamSessionCookie(minted.token, remainingSessionMaxAge(minted.session, now)),
      },
    });
  } catch (err) {
    return fail(err);
  }
}

export async function handleTeamOidcLogout(request: Request, deps: TeamHttpDeps = {}): Promise<Response> {
  try {
    requireHttps(request);
    if (request.method !== "POST") return json(405, { error: "login failed" });
    if (!sameOrigin(request)) return json(401, { error: "login failed" });
    const { sql, now } = await depsOrLoad(deps);
    const token = readTeamSessionToken(request.headers.get("cookie"));
    if (token) await revokeTeamSession(sql, token, now);
    return json(200, { ok: true }, { "Set-Cookie": clearTeamSessionCookie() });
  } catch (err) {
    const res = fail(err);
    const headers = new Headers(res.headers);
    headers.set("Set-Cookie", clearTeamSessionCookie());
    return new Response(res.body, { status: res.status, headers });
  }
}

export async function handleTeamSession(request: Request, deps: TeamHttpDeps = {}): Promise<Response> {
  try {
    requireHttps(request);
    const { sql, now } = await depsOrLoad(deps);
    const token = readTeamSessionToken(request.headers.get("cookie"));
    if (!token) return json(401, { error: "login failed" });
    const rotated = await rotateTeamSession(sql, token, now);
    if (!rotated) return json(401, { error: "login failed" });
    const headers: HeadersInit = { "content-type": "application/json" };
    if (rotated.token !== token) {
      (headers as Record<string, string>)["Set-Cookie"] = serializeTeamSessionCookie(
        rotated.token,
        remainingSessionMaxAge(rotated.session, now),
      );
    }
    return new Response(
      JSON.stringify({ userKey: rotated.session.userKey, tenantId: rotated.session.tenantId }),
      { status: 200, headers },
    );
  } catch (err) {
    return fail(err);
  }
}
