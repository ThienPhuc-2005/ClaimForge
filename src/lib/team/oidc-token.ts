import type { TeamOidcConfig } from "./oidc-config.ts";
import { oidcClientSecret } from "./oidc-config.ts";
import { TeamAuthError } from "./errors.ts";
import { postTeamOutbound } from "./outbound.ts";

export async function exchangeAuthorizationCode(
  config: TeamOidcConfig,
  input: { code: string; codeVerifier: string; fetchImpl?: typeof fetch },
): Promise<{ idToken: string }> {
  if (!input.code || !input.codeVerifier) throw new TeamAuthError("login failed");
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code: input.code,
    redirect_uri: config.redirectUri,
    client_id: config.clientId,
    client_secret: oidcClientSecret(config),
    code_verifier: input.codeVerifier,
  });
  const { json } = await postTeamOutbound(config.tokenEndpoint, {
    allowlist: config.hostnameAllowlist,
    body,
    fetchImpl: input.fetchImpl,
  });
  if (!json || typeof json !== "object" || Array.isArray(json)) {
    throw new TeamAuthError("login failed");
  }
  const idToken = (json as { id_token?: unknown }).id_token;
  if (typeof idToken !== "string" || !idToken || idToken.split(".").length !== 3) {
    throw new TeamAuthError("login failed");
  }
  return { idToken };
}
