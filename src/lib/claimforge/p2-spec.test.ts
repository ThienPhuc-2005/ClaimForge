import assert from "node:assert/strict";
import { test } from "node:test";
import { buildSpecCoverage, normalizeTemplate } from "./spec.ts";
import { analyze } from "./analyze.ts";
import type { CapturedRequest } from "./types.ts";

function req(method: string, template: string, status = 200, path = template): CapturedRequest {
  return {
    id: `${method} ${template}`,
    actor: "A",
    startedAt: 1,
    method,
    url: `https://shop.lab${path}`,
    origin: "https://shop.lab",
    path,
    template,
    query: {},
    requestHeaders: [],
    status,
    statusText: "OK",
    responseHeaders: [],
    timeMs: 0,
  };
}

test("normalizeTemplate collapses templated segments", () => {
  assert.equal(normalizeTemplate("/users/{id}/invoices/{invoiceId}"), "/users/{}/invoices/{}");
  assert.equal(normalizeTemplate("/users/{uuid}"), "/users/{}");
  assert.equal(normalizeTemplate("/health"), "/health");
});

const OPENAPI = JSON.stringify({
  openapi: "3.0.0",
  info: { title: "Shop", version: "1.0" },
  security: [{ bearer: [] }],
  paths: {
    "/users/{id}": { get: { summary: "get user" } },
    "/admin/purge": { post: { summary: "danger" } },
    "/public/health": { get: { security: [] } },
  },
});

test("coverage: declared vs observed, untested ranked by security/write", () => {
  const reqs = [req("GET", "/users/{id}", 200, "/users/42")];
  const cov = buildSpecCoverage(OPENAPI, reqs)!;
  assert.equal(cov.source, "openapi3");
  assert.equal(cov.declaredCount, 3);
  assert.equal(cov.coveredCount, 1);
  const untestedKeys = cov.untested.map((o) => `${o.method} ${o.normalized}`);
  assert.ok(untestedKeys.includes("POST /admin/purge"));
  assert.ok(untestedKeys.includes("GET /public/health"));
  // security-relevant (admin write) sorts before the public one
  assert.equal(cov.untested[0]!.normalized, "/admin/purge");
  assert.equal(cov.untested[0]!.secured, true);
});

test("security: op-level security:[] overrides global secured default", () => {
  const cov = buildSpecCoverage(OPENAPI, [])!;
  const pub = cov.untested.find((o) => o.normalized === "/public/health")!;
  assert.equal(pub.secured, false);
  const user = cov.untested.find((o) => o.normalized === "/users/{}")!;
  assert.equal(user.secured, true);
});

test("shadow: observed route not in the spec is flagged, static assets ignored", () => {
  const reqs = [
    req("GET", "/users/{id}", 200, "/users/42"),
    req("GET", "/internal/debug", 200),
    req("GET", "/assets/app.js", 200),
  ];
  const cov = buildSpecCoverage(OPENAPI, reqs)!;
  const shadowKeys = cov.shadow.map((s) => `${s.method} ${s.template}`);
  assert.ok(shadowKeys.includes("GET /internal/debug"));
  assert.ok(!shadowKeys.some((k) => k.includes("/assets/")));
});

test("Swagger 2 basePath is prefixed before matching", () => {
  const swagger = JSON.stringify({
    swagger: "2.0",
    info: { title: "s", version: "1" },
    basePath: "/api/v1",
    paths: { "/orders/{id}": { get: {} } },
  });
  const cov = buildSpecCoverage(swagger, [req("GET", "/api/v1/orders/{id}", 200, "/api/v1/orders/7")])!;
  assert.equal(cov.source, "swagger2");
  assert.equal(cov.coveredCount, 1);
});

test("YAML and invalid JSON return a spec error, not a crash", () => {
  assert.match(buildSpecCoverage("openapi: 3.0.0\npaths:", [])!.error ?? "", /JSON/i);
  assert.match(buildSpecCoverage("{ not json", [])!.error ?? "", /Invalid JSON/i);
});

test("empty spec yields undefined coverage", () => {
  assert.equal(buildSpecCoverage("", []), undefined);
  assert.equal(buildSpecCoverage("   ", []), undefined);
});

// Regression: non-numeric path params (usernames, slugs) must match by segment.
test("non-numeric path params match the declared template", () => {
  const spec = JSON.stringify({
    openapi: "3.0.0",
    info: { title: "s", version: "1" },
    paths: { "/users/{username}": { get: {} }, "/products/{category}": { get: {} } },
  });
  const reqs = [
    req("GET", "/users/{slug}", 200, "/users/alice"),
    req("GET", "/products/{slug}", 200, "/products/electronics"),
  ];
  const cov = buildSpecCoverage(spec, reqs)!;
  assert.equal(cov.coveredCount, 2);
  assert.equal(cov.untested.length, 0);
  assert.equal(cov.shadow.length, 0);
});

// Regression: third-party telemetry hosts in a HAR are not the audited API's shadow.
test("requests to other hosts are out of scope for a host-scoped spec", () => {
  const spec = JSON.stringify({
    openapi: "3.0.0",
    info: { title: "s", version: "1" },
    servers: [{ url: "https://shop.lab" }],
    paths: { "/users/{id}": { get: {} } },
  });
  const shopReq = req("GET", "/users/{id}", 200, "/users/42");
  const thirdParty: CapturedRequest = {
    ...req("POST", "/v1/track", 200, "/v1/track"),
    url: "https://api.segment.io/v1/track",
    origin: "https://api.segment.io",
  };
  const cov = buildSpecCoverage(spec, [shopReq, thirdParty])!;
  assert.equal(cov.coveredCount, 1);
  assert.equal(cov.shadow.length, 0);
});

// Regression: a 404/401/403/5xx-only probe never meaningfully exercised the endpoint.
test("an endpoint only seen with an error status stays untested", () => {
  const spec = JSON.stringify({
    openapi: "3.0.0",
    info: { title: "s", version: "1" },
    security: [{ bearer: [] }],
    paths: { "/accounts/{id}": { delete: { summary: "delete account" } } },
  });
  const cov = buildSpecCoverage(spec, [req("DELETE", "/accounts/{id}", 404, "/accounts/999")])!;
  assert.equal(cov.coveredCount, 0);
  assert.equal(cov.untested.length, 1);
  assert.equal(cov.untested[0]!.secured, true);
});

test("analyze() surfaces spec coverage as findings", () => {
  const har = JSON.stringify({
    log: {
      entries: [
        {
          startedDateTime: "2026-01-01T00:00:00Z",
          request: { method: "GET", url: "https://shop.lab/users/42", headers: [] },
          response: { status: 200, headers: [], content: { text: "{}" } },
        },
      ],
    },
  });
  const ws = analyze(har, "", "A", "B", undefined, OPENAPI);
  assert.ok(ws.specCoverage);
  assert.ok(ws.findings.some((f) => f.reasonCodes.includes("SPEC_ENDPOINT_UNTESTED")));
});
