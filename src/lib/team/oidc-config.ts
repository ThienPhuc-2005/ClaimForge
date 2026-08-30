import { inspectTeamOutboundUrl } from "./outbound.ts";
import { deriveSealKey } from "./oidc-seal.ts";
import { TeamAuthError } from "./errors.ts";

const MIN_SEAL = 32;
const MIN_SECRET = 16;

export type TeamOidcConfig = {
  readonly issuer: string;
  readonly clientId: string;
  readonly redirectUri: string;
  readonly authorizationEndpoint: string;
  readonly tokenEndpoint: string;
  readonly jwksUri: string;
  readonly hostnameAllowlist: readonly string[];
};

type BoundSecrets = {
  readonly clientSecret: string;
  readonly sealKey: Buffer;
};

const issued = new WeakMap<TeamOidcConfig, BoundSecrets>();

function read(env: Record<string, string | undefined>, key: string): string {
  const value = env[key];
  return typeof value === "string" ? value.trim() : "";
}

function parseAllowlist(raw: string): string[] {
  const hosts = raw
    .split(",")
    .map((h) => h.trim().toLowerCase().replace(/\.$/, ""))
    .filter(Boolean);
  return [...new Set(hosts)];
}

function httpsUrl(raw: string): URL | null {
  try {
    const url = new URL(raw);
    if (url.protocol !== "https:") return null;
    if (url.username || url.password) return null;
    return url;
  } catch {
    return null;
  }
}

export function inspectTeamOidcEnv(env: Record<string, string | undefined> = process.env): {
  ok: boolean;
  issues: string[];
} {
  const issues: string[] = [];
  const issuer = read(env, "CLAIMFORGE_TEAM_OIDC_ISSUER");
  const clientId = read(env, "CLAIMFORGE_TEAM_OIDC_CLIENT_ID");
  const clientSecret = read(env, "CLAIMFORGE_TEAM_OIDC_CLIENT_SECRET");
  const redirectUri = read(env, "CLAIMFORGE_TEAM_OIDC_REDIRECT_URI");
  const authorizationEndpoint = read(env, "CLAIMFORGE_TEAM_OIDC_AUTHORIZATION_ENDPOINT");
  const tokenEndpoint = read(env, "CLAIMFORGE_TEAM_OIDC_TOKEN_ENDPOINT");
  const jwksUri = read(env, "CLAIMFORGE_TEAM_OIDC_JWKS_URI");
  const allowRaw = read(env, "CLAIMFORGE_TEAM_OIDC_ALLOWED_HOSTS");
  const seal = read(env, "CLAIMFORGE_TEAM_SEAL_KEY");

  if (!issuer) issues.push("issuer is required");
  if (!clientId) issues.push("client_id is required");
  if (!clientSecret || clientSecret.length < MIN_SECRET) issues.push("client_secret is required");
  if (!redirectUri) issues.push("redirect_uri is required");
  if (!authorizationEndpoint) issues.push("authorization_endpoint is required");
  if (!tokenEndpoint) issues.push("token_endpoint is required");
  if (!jwksUri) issues.push("jwks_uri is required");
  const allowlist = parseAllowlist(allowRaw);
  if (allowlist.length === 0) issues.push("hostname allowlist is required");
  if (!seal || seal.length < MIN_SEAL) issues.push("seal key is required");

  const redirect = httpsUrl(redirectUri);
  if (redirectUri && !redirect) issues.push("redirect_uri must be HTTPS");

  const issuerUrl = httpsUrl(issuer);
  if (issuer && !issuerUrl) issues.push("issuer must be HTTPS");

  if (allowlist.length) {
    for (const [label, value] of [
      ["issuer", issuer],
      ["authorization_endpoint", authorizationEndpoint],
      ["token_endpoint", tokenEndpoint],
      ["jwks_uri", jwksUri],
    ] as const) {
      if (!value) continue;
      const gate = inspectTeamOutboundUrl(value, allowlist);
      if (!gate.ok) issues.push(`${label} is not allowed`);
    }
  }

  return { ok: issues.length === 0, issues };
}

export function loadTeamOidcConfig(
  env: Record<string, string | undefined> = process.env,
): TeamOidcConfig {
  const inspected = inspectTeamOidcEnv(env);
  if (!inspected.ok) throw new TeamAuthError("oidc is not configured");
  const config = Object.freeze({
    issuer: read(env, "CLAIMFORGE_TEAM_OIDC_ISSUER"),
    clientId: read(env, "CLAIMFORGE_TEAM_OIDC_CLIENT_ID"),
    redirectUri: read(env, "CLAIMFORGE_TEAM_OIDC_REDIRECT_URI"),
    authorizationEndpoint: read(env, "CLAIMFORGE_TEAM_OIDC_AUTHORIZATION_ENDPOINT"),
    tokenEndpoint: read(env, "CLAIMFORGE_TEAM_OIDC_TOKEN_ENDPOINT"),
    jwksUri: read(env, "CLAIMFORGE_TEAM_OIDC_JWKS_URI"),
    hostnameAllowlist: Object.freeze(parseAllowlist(read(env, "CLAIMFORGE_TEAM_OIDC_ALLOWED_HOSTS"))),
  }) as TeamOidcConfig;
  issued.set(
    config,
    Object.freeze({
      clientSecret: read(env, "CLAIMFORGE_TEAM_OIDC_CLIENT_SECRET"),
      sealKey: deriveSealKey(read(env, "CLAIMFORGE_TEAM_SEAL_KEY")),
    }),
  );
  return config;
}

function boundSecrets(config: TeamOidcConfig): BoundSecrets {
  const bound = issued.get(config);
  if (!bound) throw new TeamAuthError("oidc is not configured");
  return bound;
}

export function oidcClientSecret(config: TeamOidcConfig): string {
  return boundSecrets(config).clientSecret;
}

export function oidcSealKey(config: TeamOidcConfig): Buffer {
  return boundSecrets(config).sealKey;
}

export function redactedOidcConfig(config: TeamOidcConfig): Record<string, unknown> {
  return {
    issuer: config.issuer,
    clientId: config.clientId,
    redirectUri: config.redirectUri,
    authorizationEndpoint: config.authorizationEndpoint,
    tokenEndpoint: config.tokenEndpoint,
    jwksUri: config.jwksUri,
    hostnameAllowlist: [...config.hostnameAllowlist],
    clientSecret: "[redacted]",
    sealKey: "[redacted]",
  };
}
