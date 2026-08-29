import assert from "node:assert/strict";
import { test } from "node:test";
import { applySecurityHeaders, CSP_VALUE, productionSecurityHeaders } from "./security-headers.ts";

test("production CSP allows grok.com, workers, JWKS connect, and denies framing", () => {
  assert.match(CSP_VALUE, /https:\/\/grok\.com/);
  assert.match(CSP_VALUE, /worker-src[^;]*blob:/);
  assert.match(CSP_VALUE, /worker-src[^;]*'self'/);
  assert.match(CSP_VALUE, /connect-src[^;]*https:/);
  assert.match(CSP_VALUE, /frame-ancestors 'none'/);
  assert.doesNotMatch(CSP_VALUE, /'unsafe-eval'/);
  assert.doesNotMatch(CSP_VALUE, /frame-ancestors \*/);
});

test("security header set includes nosniff, referrer, permissions, frame deny", () => {
  const h = productionSecurityHeaders();
  assert.equal(h["X-Content-Type-Options"], "nosniff");
  assert.equal(h["Referrer-Policy"], "no-referrer");
  assert.match(h["Permissions-Policy"] ?? "", /camera=\(\)/);
  assert.match(h["Permissions-Policy"] ?? "", /geolocation=\(\)/);
  assert.equal(h["X-Frame-Options"], "DENY");
  assert.match(h["Content-Security-Policy"] ?? "", /script-src[^;]*https:\/\/grok\.com/);
});

test("applySecurityHeaders does not overwrite an existing CSP", () => {
  const existing = new Headers({ "Content-Security-Policy": "default-src 'none'" });
  const out = applySecurityHeaders(existing);
  assert.equal(out.get("Content-Security-Policy"), "default-src 'none'");
  assert.equal(out.get("X-Content-Type-Options"), "nosniff");
  assert.equal(out.get("X-Frame-Options"), "DENY");
});
