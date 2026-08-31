import { createLocalJWKSet, errors, type JSONWebKeySet, type JWTVerifyGetKey } from "jose";
import { fetchJwksDocument } from "../claimforge/jwks-fetch.ts";
import type { TeamOidcConfig } from "./oidc-config.ts";
import { teamOutboundPolicy } from "./outbound.ts";

export const TEAM_JWKS_TTL_MS = 5 * 60 * 1000;

type CacheEntry = {
  uri: string;
  at: number;
  keys: unknown[];
};

let cache: CacheEntry | null = null;

export function resetTeamJwksCache(): void {
  cache = null;
}

export async function fetchTeamJwks(
  config: TeamOidcConfig,
  opts: { fetchImpl?: typeof fetch; force?: boolean; now?: number } = {},
): Promise<JSONWebKeySet> {
  const now = opts.now ?? Date.now();
  if (
    !opts.force &&
    cache &&
    cache.uri === config.jwksUri &&
    now - cache.at < TEAM_JWKS_TTL_MS
  ) {
    return { keys: cache.keys as JSONWebKeySet["keys"] };
  }
  const { jwks } = await fetchJwksDocument(config.jwksUri, {
    confirmed: true,
    fetchImpl: opts.fetchImpl,
    policy: teamOutboundPolicy(config.hostnameAllowlist),
  });
  cache = { uri: config.jwksUri, at: now, keys: jwks.keys };
  return { keys: jwks.keys as JSONWebKeySet["keys"] };
}

/** Local JWK set. Unknown kid triggers at most one forced refetch. */
export async function teamJwkProvider(
  config: TeamOidcConfig,
  opts: { fetchImpl?: typeof fetch } = {},
): Promise<JWTVerifyGetKey> {
  let jwks = await fetchTeamJwks(config, opts);
  let getKey = createLocalJWKSet(jwks);
  let refetched = false;
  return async (header, token) => {
    try {
      return await getKey(header, token);
    } catch (err) {
      const unknownKid = err instanceof errors.JWKSNoMatchingKey;
      if (!unknownKid || refetched) throw err;
      refetched = true;
      jwks = await fetchTeamJwks(config, { ...opts, force: true });
      getKey = createLocalJWKSet(jwks);
      return await getKey(header, token);
    }
  };
}
