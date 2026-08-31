import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { fetchJwksDocument } from "../claimforge/jwks-fetch.ts";
import { inspectTeamOidcEnv, loadTeamOidcConfig, oidcClientSecret, oidcSealKey, redactedOidcConfig } from "./oidc-config.ts";
import { verifyTeamIdToken } from "./oidc-id-token.ts";
import { fetchTeamJwks, resetTeamJwksCache, TEAM_JWKS_TTL_MS } from "./oidc-jwks.ts";
import { hashOidcState, pkceChallenge } from "./oidc-pkce.ts";
import { deriveSealKey, sealUtf8, unsealUtf8 } from "./oidc-seal.ts";
import { exchangeAuthorizationCode } from "./oidc-token.ts";
import { oidcUserKey } from "./oidc-user-key.ts";
import { inspectTeamOutboundUrl, postTeamOutbound, TEAM_FETCH_MAX_BYTES } from "./outbound.ts";
import { TeamAuthError, TeamValidationError } from "./errors.ts";

const SEAL = "claimforge-team-seal-key-32bytes!";
const SECRET = "confidential-client-secret-value";

function testEnv(over: Record<string, string | undefined> = {}): Record<string, string | undefined> {
  return {
    CLAIMFORGE_TEAM_OIDC_ISSUER: "https://idp.example",
    CLAIMFORGE_TEAM_OIDC_CLIENT_ID: "claimforge",
    CLAIMFORGE_TEAM_OIDC_CLIENT_SECRET: SECRET,
    CLAIMFORGE_TEAM_OIDC_REDIRECT_URI: "https://app.example/api/team/oidc/callback",
    CLAIMFORGE_TEAM_OIDC_AUTHORIZATION_ENDPOINT: "https://idp.example/authorize",
    CLAIMFORGE_TEAM_OIDC_TOKEN_ENDPOINT: "https://idp.example/token",
    CLAIMFORGE_TEAM_OIDC_JWKS_URI: "https://idp.example/jwks",
    CLAIMFORGE_TEAM_OIDC_ALLOWED_HOSTS: "idp.example",
    CLAIMFORGE_TEAM_SEAL_KEY: SEAL,
    ...over,
  };
}

test("user_key is oidc: plus sha256 of JSON [iss, sub]", () => {
  const expected = "oidc:" + createHash("sha256").update(JSON.stringify(["https://idp.example", "user-1"]), "utf8").digest("hex");
  assert.equal(oidcUserKey("https://idp.example", "user-1"), expected);
  assert.notEqual(oidcUserKey("https://idp.example/a", "b"), oidcUserKey("https://idp.example", "a/b"));
  assert.equal(oidcUserKey("https://idp.example", "user-1").startsWith("oidc:"), true);
  assert.equal(oidcUserKey("https://idp.example", "user-1").length, 5 + 64);
  assert.throws(() => oidcUserKey("", "user-1"), TeamValidationError);
  assert.throws(() => oidcUserKey("https://idp.example", 1 as never), TeamValidationError);
  assert.notEqual(oidcUserKey("https://idp.example", "alice"), oidcUserKey("https://idp.example", " alice "));
  assert.notEqual(oidcUserKey("https://idp.example", "alice"), oidcUserKey("https://idp.example", "alice "));
  assert.equal(
    oidcUserKey("https://idp.example", " alice "),
    "oidc:" + createHash("sha256").update(JSON.stringify(["https://idp.example", " alice "]), "utf8").digest("hex"),
  );
});

test("RFC 7636 S256 challenge vector and state is hashed", () => {
  const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
  assert.equal(pkceChallenge(verifier), "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
  const state = "plain-state-value";
  assert.equal(hashOidcState(state), createHash("sha256").update(state, "utf8").digest("hex"));
  assert.notEqual(hashOidcState(state), state);
});

test("seal round-trips and rejects the wrong key", () => {
  const key = deriveSealKey(SEAL);
  const blob = sealUtf8("pkce-verifier-secret", key);
  assert.equal(blob.startsWith("v1."), true);
  assert.equal(unsealUtf8(blob, key), "pkce-verifier-secret");
  assert.throws(() => unsealUtf8(blob, deriveSealKey(SEAL.replace("!", "?"))), TeamAuthError);
  assert.doesNotMatch(blob, /pkce-verifier-secret/);
});

test("OIDC config fail-closes without allowlist, seal, issuer, or endpoints", () => {
  assert.equal(inspectTeamOidcEnv(testEnv()).ok, true);
  assert.equal(inspectTeamOidcEnv(testEnv({ CLAIMFORGE_TEAM_OIDC_ALLOWED_HOSTS: "" })).ok, false);
  assert.equal(inspectTeamOidcEnv(testEnv({ CLAIMFORGE_TEAM_SEAL_KEY: "short" })).ok, false);
  assert.equal(inspectTeamOidcEnv(testEnv({ CLAIMFORGE_TEAM_OIDC_ISSUER: "" })).ok, false);
  assert.equal(inspectTeamOidcEnv(testEnv({ CLAIMFORGE_TEAM_OIDC_TOKEN_ENDPOINT: "" })).ok, false);
  assert.equal(inspectTeamOidcEnv(testEnv({ CLAIMFORGE_TEAM_OIDC_CLIENT_SECRET: "" })).ok, false);
  assert.equal(inspectTeamOidcEnv(testEnv({ CLAIMFORGE_TEAM_OIDC_REDIRECT_URI: "http://app.example/cb" })).ok, false);
  assert.equal(
    inspectTeamOidcEnv(testEnv({ CLAIMFORGE_TEAM_OIDC_TOKEN_ENDPOINT: "https://10.0.0.5/token" })).ok,
    false,
  );
  assert.throws(() => loadTeamOidcConfig(testEnv({ CLAIMFORGE_TEAM_SEAL_KEY: "" })), TeamAuthError);
});

test("config secrets live in WeakMap and do not serialize", () => {
  const config = loadTeamOidcConfig(testEnv());
  assert.equal(oidcClientSecret(config), SECRET);
  assert.equal(oidcSealKey(config).length, 32);
  const json = JSON.stringify(config);
  assert.doesNotMatch(json, new RegExp(SECRET));
  assert.doesNotMatch(json, new RegExp(SEAL));
  assert.equal(json.includes("clientSecret"), false);
  const redacted = JSON.stringify(redactedOidcConfig(config));
  assert.doesNotMatch(redacted, new RegExp(SECRET));
  assert.match(redacted, /\[redacted\]/);
});

test("team outbound gate reuses JWKS SSRF policy", () => {
  const allow = ["idp.example"];
  assert.equal(inspectTeamOutboundUrl("https://idp.example/token", allow).ok, true);
  assert.equal(inspectTeamOutboundUrl("https://evil.example/token", allow).ok, false);
  assert.equal(inspectTeamOutboundUrl("https://10.0.0.5/token", allow).ok, false);
  assert.equal(inspectTeamOutboundUrl("http://idp.example/token", allow).ok, false);
});

function jsonResponse(body: unknown, init: ResponseInit = {}) {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "content-type": "application/json", ...((init.headers as Record<string, string>) ?? {}) },
    ...init,
  });
}

test("token POST uses credentials omit, denies redirects, and drops extra tokens", async () => {
  const config = loadTeamOidcConfig(testEnv());
  let seen: RequestInit | undefined;
  const fetchImpl = (async (_input: RequestInfo | URL, init?: RequestInit) => {
    seen = init;
    return jsonResponse({
      id_token: "aaa.bbb.ccc",
      access_token: "should-not-be-returned",
      refresh_token: "should-not-be-returned",
    });
  }) as typeof fetch;
  const out = await exchangeAuthorizationCode(config, {
    code: "splendid-code",
    codeVerifier: "verifier",
    fetchImpl,
  });
  assert.equal(out.idToken, "aaa.bbb.ccc");
  assert.equal(seen?.credentials, "omit");
  assert.equal(seen?.redirect, "manual");
  assert.equal(seen?.method, "POST");
  assert.equal("access_token" in out, false);

  const redirecting = (async () =>
    new Response(null, { status: 302, headers: { location: "https://10.0.0.5/token" } })) as typeof fetch;
  await assert.rejects(
    () => exchangeAuthorizationCode(config, { code: "x", codeVerifier: "y", fetchImpl: redirecting }),
    TeamAuthError,
  );
});

test("token POST error messages do not include code or tokens", async () => {
  const config = loadTeamOidcConfig(testEnv());
  const fetchImpl = (async () => {
    throw new Error("authorization code splendid-code leaked");
  }) as typeof fetch;
  await assert.rejects(async () => {
    try {
      await exchangeAuthorizationCode(config, { code: "splendid-code", codeVerifier: "pkce", fetchImpl });
    } catch (err) {
      assert.doesNotMatch((err as Error).message, /splendid-code|pkce|access_token/);
      throw err;
    }
  }, TeamAuthError);
});

test("token POST to a private host is denied before fetch", async () => {
  let called = 0;
  const fetchImpl = (async () => {
    called += 1;
    return jsonResponse({});
  }) as typeof fetch;
  await assert.rejects(
    () =>
      postTeamOutbound("https://10.0.0.5/token", {
        allowlist: ["10.0.0.5"],
        body: new URLSearchParams({ code: "x" }),
        fetchImpl,
      }),
    TeamAuthError,
  );
  assert.equal(called, 0);
});

test("token POST audit action is token-exchange not jwks-fetch", async () => {
  const config = loadTeamOidcConfig(testEnv());
  const { audit } = await postTeamOutbound(config.tokenEndpoint, {
    allowlist: config.hostnameAllowlist,
    body: new URLSearchParams({ grant_type: "authorization_code" }),
    fetchImpl: (async () => jsonResponse({ id_token: "aaa.bbb.ccc" })) as typeof fetch,
  });
  assert.equal(audit.action, "token-exchange");

  try {
    await postTeamOutbound(config.tokenEndpoint, {
      allowlist: config.hostnameAllowlist,
      body: new URLSearchParams({ grant_type: "authorization_code" }),
      fetchImpl: (async () => new Response(null, { status: 302, headers: { location: "https://idp.example/x" } })) as typeof fetch,
    });
    assert.fail("expected reject");
  } catch (err) {
    assert.equal((err as { audit?: { action?: string } }).audit?.action, "token-exchange");
  }
});

test("token POST stops reading when the body exceeds the size cap", async () => {
  const config = loadTeamOidcConfig(testEnv());
  let pulled = 0;
  const cap = 1024;
  const fetchImpl = (async () => {
    const stream = new ReadableStream<Uint8Array>({
      pull(controller) {
        pulled += 1;
        if (pulled === 1) controller.enqueue(new Uint8Array(cap));
        else {
          controller.enqueue(new Uint8Array(1));
          controller.close();
        }
      },
    });
    return new Response(stream, { status: 200, headers: { "content-type": "application/json" } });
  }) as typeof fetch;
  await assert.rejects(
    () =>
      postTeamOutbound(config.tokenEndpoint, {
        allowlist: config.hostnameAllowlist,
        body: new URLSearchParams({ code: "x" }),
        fetchImpl,
        maxBytes: cap,
      }),
    TeamAuthError,
  );
  assert.equal(pulled, 2);
  assert.ok(pulled < 8);

  let fetched = 0;
  const oversizedHeader = (async () => {
    fetched += 1;
    return new Response("{}", {
      status: 200,
      headers: { "content-type": "application/json", "content-length": String(TEAM_FETCH_MAX_BYTES + 1) },
    });
  }) as typeof fetch;
  await assert.rejects(
    () =>
      postTeamOutbound(config.tokenEndpoint, {
        allowlist: config.hostnameAllowlist,
        body: new URLSearchParams({ code: "x" }),
        fetchImpl: oversizedHeader,
      }),
    TeamAuthError,
  );
  assert.equal(fetched, 1);
});

test("JWKS fetch stops reading when the body exceeds the size cap", async () => {
  let pulled = 0;
  const cap = 1024;
  const fetchImpl = (async () => {
    const stream = new ReadableStream<Uint8Array>({
      pull(controller) {
        pulled += 1;
        if (pulled === 1) controller.enqueue(new Uint8Array(cap));
        else {
          controller.enqueue(new Uint8Array(1));
          controller.close();
        }
      },
    });
    return new Response(stream, { status: 200, headers: { "content-type": "application/json" } });
  }) as typeof fetch;
  await assert.rejects(
    () => fetchJwksDocument("https://idp.example/jwks", { confirmed: true, fetchImpl, maxBytes: cap }),
    /exceeds/,
  );
  assert.equal(pulled, 2);
  assert.ok(pulled < 8);
});

async function rsaKid(kid: string) {
  const pair = await generateKeyPair("RS256", { extractable: true });
  const jwk = await exportJWK(pair.publicKey);
  jwk.kid = kid;
  jwk.alg = "RS256";
  jwk.use = "sig";
  return { ...pair, jwk };
}

test("JWKS cache hits within TTL and refetches at most once for unknown kid", async () => {
  resetTeamJwksCache();
  const config = loadTeamOidcConfig(testEnv());
  const k1 = await rsaKid("k1");
  const k2 = await rsaKid("k2");
  let calls = 0;
  const fetchImpl = (async () => {
    calls += 1;
    const keys = calls === 1 ? [k1.jwk] : [k1.jwk, k2.jwk];
    return jsonResponse({ keys });
  }) as typeof fetch;

  await fetchTeamJwks(config, { fetchImpl, now: 1_000 });
  await fetchTeamJwks(config, { fetchImpl, now: 1_000 + TEAM_JWKS_TTL_MS - 1 });
  assert.equal(calls, 1);

  const nonce = "n1";
  const tokenK2 = await new SignJWT({ nonce, sub: "user-1" })
    .setProtectedHeader({ alg: "RS256", kid: "k2" })
    .setIssuer(config.issuer)
    .setAudience(config.clientId)
    .setIssuedAt(new Date(1_700_000_000_000))
    .setExpirationTime(new Date(1_700_000_000_000 + 300_000))
    .sign(k2.privateKey);

  const claims = await verifyTeamIdToken(tokenK2, {
    config,
    nonce,
    fetchImpl,
    now: new Date(1_700_000_000_000),
  });
  assert.equal(claims.sub, "user-1");
  assert.equal(calls, 2);

  resetTeamJwksCache();
  calls = 0;
  const missing = await new SignJWT({ nonce, sub: "user-1" })
    .setProtectedHeader({ alg: "RS256", kid: "missing" })
    .setIssuer(config.issuer)
    .setAudience(config.clientId)
    .setIssuedAt(new Date(1_700_000_000_000))
    .setExpirationTime(new Date(1_700_000_000_000 + 300_000))
    .sign(k1.privateKey);
  const once = (async () => {
    calls += 1;
    return jsonResponse({ keys: [k1.jwk] });
  }) as typeof fetch;
  await assert.rejects(() => verifyTeamIdToken(missing, { config, nonce, fetchImpl: once, now: new Date(1_700_000_000_000) }), TeamAuthError);
  assert.equal(calls, 2);
});

test("ID token rejects none, HS256, wrong aud, nonce, exp, and issuer", async () => {
  resetTeamJwksCache();
  const config = loadTeamOidcConfig(testEnv());
  const k1 = await rsaKid("k1");
  const fetchImpl = (async () => jsonResponse({ keys: [k1.jwk] })) as typeof fetch;
  const now = new Date(1_700_000_000_000);
  async function mint(over: { alg?: string; nonce?: string; aud?: string | string[]; expMs?: number; iss?: string; kid?: string }) {
    const alg = over.alg ?? "RS256";
    const jwt = new SignJWT({ nonce: over.nonce ?? "n1", sub: "user-1" })
      .setProtectedHeader({ alg, kid: over.kid ?? "k1" })
      .setIssuer(over.iss ?? config.issuer)
      .setAudience(over.aud ?? config.clientId)
      .setIssuedAt(now);
    if (over.expMs !== undefined) jwt.setExpirationTime(new Date(over.expMs));
    else jwt.setExpirationTime(new Date(now.getTime() + 300_000));
    return jwt.sign(k1.privateKey);
  }
  const good = await mint({});
  const ok = await verifyTeamIdToken(good, { config, nonce: "n1", fetchImpl, now });
  assert.equal(ok.iss, config.issuer);

  const none = `${Buffer.from(JSON.stringify({ alg: "none", typ: "JWT" })).toString("base64url")}.${Buffer.from(
    JSON.stringify({ sub: "user-1", nonce: "n1", iss: config.issuer, aud: config.clientId, iat: 1, exp: 9_999_999_999 }),
  ).toString("base64url")}.`;
  await assert.rejects(() => verifyTeamIdToken(none, { config, nonce: "n1", fetchImpl, now }), TeamAuthError);

  const { SignJWT: SignHS } = await import("jose");
  const hs = await new SignHS({ nonce: "n1", sub: "user-1" })
    .setProtectedHeader({ alg: "HS256" })
    .setIssuer(config.issuer)
    .setAudience(config.clientId)
    .setIssuedAt(now)
    .setExpirationTime(new Date(now.getTime() + 300_000))
    .sign(new TextEncoder().encode("not-the-client-secret-but-hmac"));
  await assert.rejects(() => verifyTeamIdToken(hs, { config, nonce: "n1", fetchImpl, now }), TeamAuthError);

  await assert.rejects(
    async () => verifyTeamIdToken(await mint({ aud: "other-app" }), { config, nonce: "n1", fetchImpl, now }),
    TeamAuthError,
  );
  await assert.rejects(
    async () => verifyTeamIdToken(await mint({}), { config, nonce: "other", fetchImpl, now }),
    TeamAuthError,
  );
  await assert.rejects(
    async () => verifyTeamIdToken(await mint({ expMs: now.getTime() - 120_000 }), { config, nonce: "n1", fetchImpl, now }),
    TeamAuthError,
  );
  await assert.rejects(
    async () => verifyTeamIdToken(await mint({ iss: "https://evil.example" }), { config, nonce: "n1", fetchImpl, now }),
    TeamAuthError,
  );
});

test("ID token rejects future iat and stale iat", async () => {
  resetTeamJwksCache();
  const config = loadTeamOidcConfig(testEnv());
  const k1 = await rsaKid("k1");
  const fetchImpl = (async () => jsonResponse({ keys: [k1.jwk] })) as typeof fetch;
  const now = new Date(1_700_000_000_000);
  async function mintIat(iatMs: number) {
    return new SignJWT({ nonce: "n1", sub: "user-1" })
      .setProtectedHeader({ alg: "RS256", kid: "k1" })
      .setIssuer(config.issuer)
      .setAudience(config.clientId)
      .setIssuedAt(new Date(iatMs))
      .setExpirationTime(new Date(now.getTime() + 300_000))
      .sign(k1.privateKey);
  }
  await assert.rejects(
    async () => verifyTeamIdToken(await mintIat(now.getTime() + 120_000), { config, nonce: "n1", fetchImpl, now }),
    TeamAuthError,
  );
  await assert.rejects(
    async () => verifyTeamIdToken(await mintIat(now.getTime() - 20 * 60_000), { config, nonce: "n1", fetchImpl, now }),
    TeamAuthError,
  );
  const ok = await verifyTeamIdToken(await mintIat(now.getTime()), { config, nonce: "n1", fetchImpl, now });
  assert.equal(ok.sub, "user-1");

  const spaced = await new SignJWT({ nonce: "n1", sub: " alice " })
    .setProtectedHeader({ alg: "RS256", kid: "k1" })
    .setIssuer(config.issuer)
    .setAudience(config.clientId)
    .setIssuedAt(now)
    .setExpirationTime(new Date(now.getTime() + 300_000))
    .sign(k1.privateKey);
  const exact = await verifyTeamIdToken(spaced, { config, nonce: "n1", fetchImpl, now });
  assert.equal(exact.sub, " alice ");
});
