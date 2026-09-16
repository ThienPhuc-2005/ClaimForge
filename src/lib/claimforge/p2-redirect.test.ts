import assert from "node:assert/strict";
import { test } from "node:test";
import { isExternalTarget, isDangerousScheme, openRedirects } from "./redirect.ts";
import { analyze } from "./analyze.ts";
import type { CapturedRequest } from "./types.ts";

function req(p: Partial<CapturedRequest>): CapturedRequest {
  return {
    id: "r",
    actor: "A",
    startedAt: 1,
    method: "GET",
    url: "https://shop.lab/auth/login",
    origin: "https://shop.lab",
    path: "/auth/login",
    template: "/auth/login",
    query: {},
    requestHeaders: [],
    status: 200,
    statusText: "OK",
    responseHeaders: [],
    timeMs: 0,
    ...p,
  };
}

function loc(v: string) {
  return [{ name: "Location", value: v }];
}

test("isExternalTarget / isDangerousScheme classify targets", () => {
  assert.equal(isExternalTarget("https://evil.test/x", "shop.lab"), true);
  assert.equal(isExternalTarget("//evil.test/x", "shop.lab"), true);
  assert.equal(isExternalTarget("/dashboard", "shop.lab"), false);
  assert.equal(isExternalTarget("https://shop.lab/dashboard", "shop.lab"), false);
  assert.equal(isDangerousScheme("javascript:alert(1)"), true);
  assert.equal(isDangerousScheme("https://evil.test"), false);
});

test("reflected off-origin redirect is a Suspicion", () => {
  const r = req({
    url: "https://shop.lab/auth/login?next=https://evil.test/x",
    status: 302,
    responseHeaders: loc("https://evil.test/x"),
  });
  const hits = openRedirects([r]);
  assert.equal(hits.length, 1);
  assert.equal(hits[0]!.confidence, "suspicion");
  assert.equal(hits[0]!.reflected, true);
  assert.ok(hits[0]!.reasonCodes.includes("OPEN_REDIRECT_REFLECTED"));
  assert.ok(hits[0]!.reasonCodes.includes("IMPACT_NOT_PROVEN"));
});

test("dangerous-scheme redirect target is flagged high", () => {
  const r = req({
    url: "https://shop.lab/go?url=javascript:alert(1)",
    path: "/go",
    template: "/go",
    status: 302,
    responseHeaders: loc("javascript:alert(1)"),
  });
  const hits = openRedirects([r]);
  assert.equal(hits.length, 1);
  assert.equal(hits[0]!.severity, "high");
  assert.ok(hits[0]!.reasonCodes.includes("OPEN_REDIRECT_DANGEROUS_SCHEME"));
});

test("same-origin redirect target is ignored (normal login flow)", () => {
  const r = req({
    url: "https://shop.lab/auth/login?next=/dashboard",
    status: 302,
    responseHeaders: loc("/dashboard"),
  });
  assert.equal(openRedirects([r]).length, 0);
});

test("off-origin target with no honoring redirect is Observation (unverified)", () => {
  const r = req({ url: "https://shop.lab/auth/login?returnTo=https://evil.test", status: 200 });
  const hits = openRedirects([r]);
  assert.equal(hits.length, 1);
  assert.equal(hits[0]!.confidence, "observation");
  assert.ok(hits[0]!.reasonCodes.includes("OPEN_REDIRECT_PARAM_UNVERIFIED"));
});

test("a non-redirect parameter carrying a URL is not flagged", () => {
  const r = req({ url: "https://shop.lab/search?q=https://evil.test", path: "/search", template: "/search", status: 200 });
  assert.equal(openRedirects([r]).length, 0);
});

test("OAuth redirect_uri off-origin is surfaced as a Suspicion candidate", () => {
  const r = req({
    url: "https://idp.lab/oauth/authorize?redirect_uri=https://client.test/cb",
    origin: "https://idp.lab",
    path: "/oauth/authorize",
    template: "/oauth/authorize",
    status: 302,
    responseHeaders: loc("https://client.test/cb?code=abc"),
  });
  const hits = openRedirects([r]);
  assert.equal(hits.length, 1);
  assert.equal(hits[0]!.confidence, "suspicion");
});

test("end-to-end: analyze() surfaces an open-redirect finding, path, and replay", () => {
  const har = JSON.stringify({
    log: {
      entries: [
        {
          startedDateTime: "2026-01-01T00:00:00Z",
          request: { method: "GET", url: "https://shop.lab/auth/login?next=https://evil.test/x", headers: [] },
          response: { status: 302, headers: [{ name: "Location", value: "https://evil.test/x" }], content: { text: "" } },
        },
      ],
    },
  });
  const ws = analyze(har, "", "A", "B");
  assert.ok(ws.findings.some((f) => (f.fingerprint ?? "").startsWith("open-redirect:")));
  assert.ok(ws.paths.some((p) => p.id === "path-open-redirect"));
  assert.ok(ws.replays.some((r) => r.id.startsWith("replay-redirect")));
});
