import { decodeProtectedHeader, jwtVerify } from "jose";
import { TeamAuthError } from "./errors.ts";
import type { TeamOidcConfig } from "./oidc-config.ts";
import { teamJwkProvider } from "./oidc-jwks.ts";

export const TEAM_ID_TOKEN_ALGS = ["RS256", "PS256", "ES256"] as const;
export const TEAM_ID_TOKEN_SKEW_SEC = 30;
/** ID token from an authorization-code exchange must be recently issued. */
export const TEAM_ID_TOKEN_MAX_AGE_SEC = 5 * 60;

function audList(aud: unknown): string[] {
  if (typeof aud === "string") return [aud];
  if (Array.isArray(aud) && aud.every((v) => typeof v === "string")) return aud;
  return [];
}

export async function verifyTeamIdToken(
  raw: string,
  opts: { config: TeamOidcConfig; nonce: string; fetchImpl?: typeof fetch; now?: Date },
): Promise<{ iss: string; sub: string }> {
  if (typeof raw !== "string" || raw.split(".").length !== 3) throw new TeamAuthError("login failed");
  let header: { alg?: unknown; kid?: unknown };
  try {
    header = decodeProtectedHeader(raw);
  } catch {
    throw new TeamAuthError("login failed");
  }
  const alg = typeof header.alg === "string" ? header.alg : "";
  if (alg === "none" || alg.toLowerCase() === "n0ne" || alg.startsWith("HS")) {
    throw new TeamAuthError("login failed");
  }
  if (!(TEAM_ID_TOKEN_ALGS as readonly string[]).includes(alg)) {
    throw new TeamAuthError("login failed");
  }
  const getKey = await teamJwkProvider(opts.config, { fetchImpl: opts.fetchImpl });
  let payload: Record<string, unknown>;
  try {
    const verified = await jwtVerify(raw, getKey, {
      algorithms: [...TEAM_ID_TOKEN_ALGS],
      issuer: opts.config.issuer,
      audience: opts.config.clientId,
      clockTolerance: TEAM_ID_TOKEN_SKEW_SEC,
      currentDate: opts.now,
    });
    payload = verified.payload as Record<string, unknown>;
  } catch {
    throw new TeamAuthError("login failed");
  }
  const sub = typeof payload.sub === "string" ? payload.sub : "";
  const iss = typeof payload.iss === "string" ? payload.iss : "";
  const nonce = typeof payload.nonce === "string" ? payload.nonce : "";
  if (!sub || !iss) throw new TeamAuthError("login failed");
  if (nonce !== opts.nonce) throw new TeamAuthError("login failed");
  const aud = audList(payload.aud);
  if (!aud.includes(opts.config.clientId)) throw new TeamAuthError("login failed");
  if (aud.length > 1) {
    if (payload.azp !== opts.config.clientId) throw new TeamAuthError("login failed");
  } else if (payload.azp !== undefined && payload.azp !== opts.config.clientId) {
    throw new TeamAuthError("login failed");
  }
  if (typeof payload.iat !== "number" || !Number.isFinite(payload.iat)) throw new TeamAuthError("login failed");
  if (typeof payload.exp !== "number") throw new TeamAuthError("login failed");
  const nowSec = Math.floor((opts.now ?? new Date()).getTime() / 1000);
  if (payload.iat > nowSec + TEAM_ID_TOKEN_SKEW_SEC) throw new TeamAuthError("login failed");
  if (payload.iat < nowSec - (TEAM_ID_TOKEN_MAX_AGE_SEC + TEAM_ID_TOKEN_SKEW_SEC)) {
    throw new TeamAuthError("login failed");
  }
  return { iss, sub };
}
