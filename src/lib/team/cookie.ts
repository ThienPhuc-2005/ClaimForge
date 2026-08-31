export const TEAM_SESSION_COOKIE = "__Host-claimforge-team.session";
export const TRUST_PROXY_ENV = "CLAIMFORGE_TEAM_TRUST_PROXY";

const ATTR = "Path=/; Secure; HttpOnly; SameSite=Strict";

export function serializeTeamSessionCookie(token: string, maxAgeSec: number): string {
  const age = Math.max(0, Math.floor(maxAgeSec));
  return `${TEAM_SESSION_COOKIE}=${token}; ${ATTR}; Max-Age=${age}`;
}

export function clearTeamSessionCookie(): string {
  return `${TEAM_SESSION_COOKIE}=; ${ATTR}; Max-Age=0`;
}

export function readTeamSessionToken(cookieHeader: string | null | undefined): string | null {
  if (!cookieHeader) return null;
  for (const part of cookieHeader.split(";")) {
    const idx = part.indexOf("=");
    if (idx < 0) continue;
    const name = part.slice(0, idx).trim();
    if (name !== TEAM_SESSION_COOKIE) continue;
    const value = part.slice(idx + 1).trim();
    return value || null;
  }
  return null;
}

/** Opt-in only. `"true"` / `"1"` / `"yes"` (case-insensitive). */
export function trustProxyEnabled(env: Record<string, string | undefined> = process.env): boolean {
  const raw = env[TRUST_PROXY_ENV];
  const value = typeof raw === "string" ? raw.trim().toLowerCase() : "";
  return value === "1" || value === "true" || value === "yes";
}

/**
 * HTTPS is the request URL protocol. `X-Forwarded-Proto` is ignored unless
 * `CLAIMFORGE_TEAM_TRUST_PROXY` is explicitly enabled.
 *
 * That flag is only safe when a trusted reverse proxy strips or overwrites
 * client-supplied `X-Forwarded-Proto`. Otherwise a caller can spoof HTTPS
 * and receive a `__Host-` session cookie on a cleartext request.
 */
export function requestIsHttps(
  request: Request,
  env: Record<string, string | undefined> = process.env,
): boolean {
  const url = new URL(request.url);
  if (url.protocol === "https:") return true;
  if (!trustProxyEnabled(env)) return false;
  const forwarded = request.headers.get("x-forwarded-proto");
  return forwarded?.split(",")[0]?.trim().toLowerCase() === "https";
}
