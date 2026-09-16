import assert from "node:assert/strict";
import { test } from "node:test";
import { refreshTokenReuse, refreshTokenPresented, refreshTokenIssued } from "./refresh.ts";
import { DEFAULT_POLICY } from "./policy.ts";
import type { CapturedRequest } from "./types.ts";

function refresh(p: Partial<CapturedRequest> & { at: number; present?: string; issue?: string }): CapturedRequest {
  const body =
    (p.present ? `grant_type=refresh_token&refresh_token=${p.present}` : "grant_type=refresh_token");
  return {
    id: p.id ?? `r${p.at}`,
    actor: p.actor ?? "A",
    startedAt: p.at,
    method: "POST",
    url: "https://shop.lab/oauth/token",
    origin: p.origin ?? "https://shop.lab",
    path: "/oauth/token",
    template: "/oauth/token",
    query: {},
    requestHeaders: [],
    requestBody: p.requestBody ?? body,
    status: p.status ?? 200,
    statusText: "OK",
    responseHeaders: [],
    responseBody: p.issue ? JSON.stringify({ access_token: "a", refresh_token: p.issue }) : undefined,
    timeMs: 0,
  };
}

test("token extraction reads presented + issued refresh tokens", () => {
  const r = refresh({ at: 1, present: "OLDTOKEN123456", issue: "NEWTOKEN654321" });
  assert.deepEqual(refreshTokenPresented(r), ["OLDTOKEN123456"]);
  assert.equal(refreshTokenIssued(r), "NEWTOKEN654321");
});

test("reuse-after-rotation is Suspicion (a grace/leeway window is legitimate), never Confirmed", () => {
  const reqs = [
    refresh({ at: 1, present: "OLDTOKEN123456", issue: "NEWTOKEN654321" }),
    refresh({ at: 2, present: "OLDTOKEN123456", issue: "NEWER0000111" }),
  ];
  const hits = refreshTokenReuse(reqs, DEFAULT_POLICY);
  assert.equal(hits.length, 1);
  assert.equal(hits[0]!.confidence, "suspicion");
  assert.equal(hits[0]!.rotationObserved, true);
  assert.ok(hits[0]!.reasonCodes.includes("REFRESH_TOKEN_REUSE"));
  assert.ok(hits[0]!.reasonCodes.includes("REFRESH_ROTATION_OBSERVED"));
  assert.ok(hits[0]!.reasonCodes.includes("IMPACT_NOT_PROVEN"));
});

// Regression: camelCase refreshToken keys (very common JSON APIs) must be read.
test("reuse detected with camelCase refreshToken JSON keys", () => {
  const reqs = [
    refresh({
      at: 1,
      requestBody: '{"grant_type":"refresh_token","refreshToken":"RTOLDAAAAAAAA"}',
      issue: undefined,
      status: 200,
    }),
    refresh({ at: 2, requestBody: '{"refreshToken":"RTOLDAAAAAAAA"}', status: 200 }),
  ];
  // manually attach camelCase issued token to req1 response
  reqs[0]!.responseBody = JSON.stringify({ accessToken: "x", refreshToken: "RTNEWBBBBBBBB" });
  const hits = refreshTokenReuse(reqs, DEFAULT_POLICY);
  assert.equal(hits.length, 1);
  assert.equal(hits[0]!.rotationObserved, true);
});

// Regression: a benign cookie whose NAME contains "refresh" on an ordinary page is not a refresh event.
test("a 'refresh'-named cookie on a normal page does not trip refresh detection", () => {
  const page = (at: number): CapturedRequest => ({
    id: `p${at}`,
    actor: "A",
    startedAt: at,
    method: "GET",
    url: "https://shop.lab/dashboard",
    origin: "https://shop.lab",
    path: "/dashboard",
    template: "/dashboard",
    query: {},
    requestHeaders: [{ name: "Cookie", value: "csrf-refresh-token=aaaaaaaaaaaaaaaa1111" }],
    status: 200,
    statusText: "OK",
    responseHeaders: [],
    timeMs: 0,
  });
  assert.equal(refreshTokenReuse([page(1), page(2)], DEFAULT_POLICY).length, 0);
});

// Regression: a refresh token presented in a request header is read.
test("reuse detected when the refresh token is in a request header", () => {
  const hdr = (at: number, issue?: string): CapturedRequest => ({
    id: `h${at}`,
    actor: "A",
    startedAt: at,
    method: "POST",
    url: "https://shop.lab/token",
    origin: "https://shop.lab",
    path: "/token",
    template: "/token",
    query: {},
    requestHeaders: [{ name: "X-Refresh-Token", value: "RTHDRAAAAAAAA" }],
    requestBody: "",
    status: 200,
    statusText: "OK",
    responseHeaders: [],
    responseBody: issue ? JSON.stringify({ refresh_token: issue }) : undefined,
    timeMs: 0,
  });
  const hits = refreshTokenReuse([hdr(1, "RTHDRNEWBBBB"), hdr(2)], DEFAULT_POLICY);
  assert.equal(hits.length, 1);
  assert.equal(hits[0]!.rotationObserved, true);
});

test("replay without observed rotation is Suspicion", () => {
  const reqs = [
    refresh({ at: 1, present: "SAMETOKEN12345" }),
    refresh({ at: 2, present: "SAMETOKEN12345" }),
  ];
  const hits = refreshTokenReuse(reqs, DEFAULT_POLICY);
  assert.equal(hits.length, 1);
  assert.equal(hits[0]!.rotationObserved, false);
  assert.equal(hits[0]!.confidence, "suspicion");
  assert.ok(hits[0]!.reasonCodes.includes("REFRESH_TOKEN_REPLAYED"));
});

test("clean rotation (old token never reused) produces no finding", () => {
  const reqs = [
    refresh({ at: 1, present: "TOK1AAAAAAAA", issue: "TOK2BBBBBBBB" }),
    refresh({ at: 2, present: "TOK2BBBBBBBB", issue: "TOK3CCCCCCCC" }),
  ];
  assert.equal(refreshTokenReuse(reqs, DEFAULT_POLICY).length, 0);
});

test("a single refresh is never a reuse", () => {
  assert.equal(refreshTokenReuse([refresh({ at: 1, present: "ONLYTOKEN0001", issue: "NEXT0002" })], DEFAULT_POLICY).length, 0);
});
