export const TEAM_SESSION_COOKIE = "__Host-claimforge-team.session";

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

export function requestIsHttps(request: Request): boolean {
  const url = new URL(request.url);
  if (url.protocol === "https:") return true;
  const forwarded = request.headers.get("x-forwarded-proto");
  return forwarded?.split(",")[0]?.trim().toLowerCase() === "https";
}
