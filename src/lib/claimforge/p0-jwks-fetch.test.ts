import assert from "node:assert/strict";
import { test } from "node:test";
import { fetchJwksDocument, inspectJwksUrl } from "./jwks-fetch.ts";

test("HTTPS ok; HTTP only loopback", () => {
  assert.equal(inspectJwksUrl("https://issuer.example/.well-known/jwks.json").ok, true);
  assert.equal(inspectJwksUrl("http://127.0.0.1:8080/jwks").ok, true);
  assert.equal(inspectJwksUrl("http://localhost/jwks").ok, true);
  assert.equal(inspectJwksUrl("http://evil.example/jwks").ok, false);
  assert.equal(inspectJwksUrl("file:///etc/passwd").ok, false);
});

test("metadata and userinfo blocked", () => {
  assert.ok(inspectJwksUrl("http://169.254.169.254/latest/meta-data").issues.length);
  assert.ok(inspectJwksUrl("https://metadata.google.internal/computeMetadata/v1").issues.some((i) => /metadata/i.test(i)));
  assert.ok(inspectJwksUrl("https://user:pass@issuer.example/jwks").issues.some((i) => /userinfo/i.test(i)));
});

test("team mode blocks RFC1918 unless allowlisted hostname", () => {
  const r = inspectJwksUrl("https://10.0.0.5/jwks", { teamMode: true });
  assert.equal(r.ok, false);
  const allow = inspectJwksUrl("https://keys.corp.example/jwks", {
    teamMode: true,
    hostnameAllowlist: ["keys.corp.example"],
  });
  assert.equal(allow.ok, true);
});

test("unconfirmed fetch is denied and does not call fetch", async () => {
  let called = 0;
  const fetchImpl = (async () => {
    called++;
    return new Response("{}", { status: 200 });
  }) as typeof fetch;
  await assert.rejects(
    () => fetchJwksDocument("https://issuer.example/jwks", { confirmed: false, fetchImpl }),
    /confirmation/i,
  );
  assert.equal(called, 0);
});

function jsonResponse(body: unknown, init: ResponseInit = {}) {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "content-type": "application/json", ...((init.headers as Record<string, string>) ?? {}) },
    ...init,
  });
}

test("happy path returns keys and audit without secrets", async () => {
  const fetchImpl = (async () => jsonResponse({ keys: [{ kty: "RSA", kid: "k1", n: "x", e: "AQAB" }] })) as typeof fetch;
  const { jwks, audit } = await fetchJwksDocument("https://issuer.example/jwks", { confirmed: true, fetchImpl });
  assert.equal(jwks.keys.length, 1);
  assert.equal(audit.result, "ok");
  assert.equal(audit.hostname, "issuer.example");
  assert.doesNotMatch(JSON.stringify(audit), /eyJ/);
});

test("oversize and wrong content-type fail", async () => {
  const big = (async () => new Response("x".repeat(70_000), { headers: { "content-type": "application/json" } })) as typeof fetch;
  await assert.rejects(() => fetchJwksDocument("https://issuer.example/jwks", { confirmed: true, fetchImpl: big, maxBytes: 100 }), /exceeds/);
  const html = (async () => new Response("{}", { headers: { "content-type": "text/html" } })) as typeof fetch;
  await assert.rejects(() => fetchJwksDocument("https://issuer.example/jwks", { confirmed: true, fetchImpl: html }), /content-type/);
});

test("redirect is revalidated; HTTP hop denied", async () => {
  const fetchImpl = (async (input: RequestInfo | URL) => {
    const href = String(input);
    if (href.includes("issuer.example")) {
      return new Response(null, { status: 302, headers: { location: "http://evil.example/jwks" } });
    }
    return jsonResponse({ keys: [] });
  }) as typeof fetch;
  await assert.rejects(
    () => fetchJwksDocument("https://issuer.example/jwks", { confirmed: true, fetchImpl }),
    /HTTP JWKS|denied|localhost/i,
  );
});

test("notice describes hostname and data movement before fetch", () => {
  const n = inspectJwksUrl("https://issuer.example/jwks").notice;
  assert.equal(n.hostname, "issuer.example");
  assert.match(n.sends, /credentials omitted/i);
  assert.match(n.receives, /JWK set/i);
});
