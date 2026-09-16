import assert from "node:assert/strict";
import { test } from "node:test";
import { csrfExposures, hasAntiCsrfToken } from "./csrf.ts";
import { DEFAULT_POLICY } from "./policy.ts";
import type { CapturedRequest, CookieRecord } from "./types.ts";

function req(p: Partial<CapturedRequest>): CapturedRequest {
  return {
    id: "r",
    actor: "A",
    startedAt: 1,
    method: "POST",
    url: "https://shop.lab/account/email",
    origin: "https://shop.lab",
    path: "/account/email",
    template: "/account/email",
    query: {},
    requestHeaders: [{ name: "Cookie", value: "session=abcdef0123456789ab" }],
    requestBody: "{}",
    status: 200,
    statusText: "OK",
    responseHeaders: [],
    timeMs: 0,
    ...p,
  };
}

function setCookie(name: string, sameSite: string | null, actor: "A" | "B" = "A"): CookieRecord {
  return {
    actor,
    name,
    value: "abcdef0123456789ab",
    source: "set-cookie",
    flags: { httpOnly: true, secure: true, sameSite },
    issues: [],
  };
}

test("CSRF suspicion: cookie-auth state change, SameSite=None, no token", () => {
  const hits = csrfExposures([req({})], [setCookie("session", "None")], DEFAULT_POLICY);
  assert.equal(hits.length, 1);
  assert.equal(hits[0]!.sameSite, "none");
  assert.equal(hits[0]!.confidence, "suspicion");
  assert.ok(hits[0]!.reasonCodes.includes("CSRF_SAMESITE_NONE"));
  assert.ok(hits[0]!.reasonCodes.includes("IMPACT_NOT_PROVEN"));
});

test("CSRF observation when SameSite was not observed (Lax default)", () => {
  const hits = csrfExposures([req({})], [], DEFAULT_POLICY);
  assert.equal(hits.length, 1);
  assert.equal(hits[0]!.sameSite, "unknown");
  assert.equal(hits[0]!.confidence, "observation");
  assert.ok(hits[0]!.reasonCodes.includes("CSRF_SAMESITE_DEFAULT_LAX"));
});

test("CSRF does not fire when a SameSite=Lax/Strict cookie protects the request", () => {
  assert.equal(csrfExposures([req({})], [setCookie("session", "Lax")], DEFAULT_POLICY).length, 0);
  assert.equal(csrfExposures([req({})], [setCookie("session", "Strict")], DEFAULT_POLICY).length, 0);
});

test("CSRF does not fire with an anti-CSRF header", () => {
  const r = req({ requestHeaders: [{ name: "Cookie", value: "session=abcdef0123456789ab" }, { name: "X-CSRF-Token", value: "t" }] });
  assert.equal(csrfExposures([r], [setCookie("session", "None")], DEFAULT_POLICY).length, 0);
});

test("CSRF does not fire with a csrf field in the body", () => {
  const r = req({ requestBody: '{"csrf_token":"abc","email":"x@y.z"}' });
  assert.equal(csrfExposures([r], [setCookie("session", "None")], DEFAULT_POLICY).length, 0);
  assert.ok(hasAntiCsrfToken(r));
});

test("CSRF does not fire on bearer-authed requests (not ambient)", () => {
  const r = req({
    requestHeaders: [
      { name: "Cookie", value: "session=abcdef0123456789ab" },
      { name: "Authorization", value: "Bearer eyJabc.def.ghi" },
    ],
  });
  assert.equal(csrfExposures([r], [setCookie("session", "None")], DEFAULT_POLICY).length, 0);
});

test("CSRF ignores safe methods and public routes", () => {
  assert.equal(csrfExposures([req({ method: "GET" })], [setCookie("session", "None")], DEFAULT_POLICY).length, 0);
  const pub = req({ path: "/public/subscribe", template: "/public/subscribe" });
  assert.equal(csrfExposures([pub], [setCookie("session", "None")], DEFAULT_POLICY).length, 0);
});

// Regression: a JSON *value* of "csrf" must not suppress a real finding.
test("CSRF: a benign body value 'csrf' does not suppress the finding", () => {
  const r = req({ requestBody: '{"title":"post","tags":"csrf"}' });
  assert.equal(hasAntiCsrfToken(r), false);
  assert.equal(csrfExposures([r], [setCookie("session", "None")], DEFAULT_POLICY).length, 1);
});

// Regression: analytics cookies are not credentials.
test("CSRF: tracking cookies (_ga/_gid) are not treated as auth", () => {
  const r = req({
    path: "/collect",
    template: "/collect",
    requestHeaders: [{ name: "Cookie", value: "_ga=GA1.2.1234567890.1234567890; _gid=GA1.2.987654321.170" }],
    status: 204,
  });
  assert.equal(csrfExposures([r], [], DEFAULT_POLICY).length, 0);
});

// Regression: a cookie with no SameSite attribute is Lax by default, not None.
test("CSRF: missing SameSite attribute is observation (Lax default), not None", () => {
  const hits = csrfExposures([req({})], [setCookie("session", null)], DEFAULT_POLICY);
  assert.equal(hits.length, 1);
  assert.equal(hits[0]!.sameSite, "unknown");
  assert.equal(hits[0]!.confidence, "observation");
});

// Regression: the least-protective record wins when a cookie is re-issued.
test("CSRF: a later SameSite=None re-issue is not masked by an earlier Lax", () => {
  const hits = csrfExposures([req({})], [setCookie("session", "Lax"), setCookie("session", "None")], DEFAULT_POLICY);
  assert.equal(hits.length, 1);
  assert.equal(hits[0]!.sameSite, "none");
});

// Regression: X-Requested-With is auto-added by frameworks and does not prove protection.
test("CSRF: X-Requested-With does not suppress the finding", () => {
  const r = req({
    requestHeaders: [
      { name: "Cookie", value: "session=abcdef0123456789ab" },
      { name: "X-Requested-With", value: "XMLHttpRequest" },
    ],
  });
  assert.equal(csrfExposures([r], [setCookie("session", "None")], DEFAULT_POLICY).length, 1);
});

// Regression: the short 'X-CSRF' header form is recognized as protection.
test("CSRF: X-CSRF header form is recognized", () => {
  const r = req({
    requestHeaders: [
      { name: "Cookie", value: "session=abcdef0123456789ab" },
      { name: "X-CSRF", value: "realtoken123" },
    ],
  });
  assert.equal(csrfExposures([r], [setCookie("session", "None")], DEFAULT_POLICY).length, 0);
});
