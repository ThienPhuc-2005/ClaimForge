import assert from "node:assert/strict";
import { test } from "node:test";
import type { CapturedRequest } from "./types.ts";
import {
  applyCredentialBoundary,
  extractActorCredentials,
  isCredentialHeader,
  replayHasForeignSecret,
  stripSourceCredentials,
} from "./replay-credentials.ts";
import { curlReplay } from "./playbook.ts";
import { analyze } from "./analyze.ts";
import { buildReport, renderReportJson, renderReportMarkdown } from "./report.ts";
import { demoActorA, demoActorB } from "./demo.ts";

function req(over: Partial<CapturedRequest> & Pick<CapturedRequest, "actor" | "requestHeaders">): CapturedRequest {
  return {
    id: over.id ?? "r",
    actor: over.actor,
    startedAt: over.startedAt ?? 1,
    method: over.method ?? "GET",
    url: over.url ?? "https://shop.lab/api/invoices/inv-a1?access_token=ALICE_QUERY_TOKEN",
    origin: over.origin ?? "https://shop.lab",
    path: over.path ?? "/api/invoices/inv-a1",
    template: over.template ?? "/api/invoices/{id}",
    query: over.query ?? { access_token: "ALICE_QUERY_TOKEN" },
    requestHeaders: over.requestHeaders,
    requestBody: over.requestBody ?? JSON.stringify({ csrf: "ALICE_BODY_CSRF", note: "ok" }),
    status: over.status ?? 200,
    statusText: "OK",
    responseHeaders: [],
    timeMs: 0,
  };
}

const ALICE: CapturedRequest = req({
  actor: "A",
  requestHeaders: [
    { name: "Authorization", value: "Bearer ALICE_BEARER_TOKEN" },
    { name: "Cookie", value: "sid=ALICE_COOKIE_VALUE" },
    { name: "X-API-Key", value: "ALICE_API_KEY_VALUE" },
    { name: "X-CSRF-Token", value: "ALICE_CSRF_HEADER" },
    { name: "Content-Type", value: "application/json" },
  ],
});

const BOB: CapturedRequest = req({
  id: "b",
  actor: "B",
  url: "https://shop.lab/api/me",
  path: "/api/me",
  template: "/api/me",
  query: {},
  requestBody: undefined,
  requestHeaders: [
    { name: "Authorization", value: "Bearer BOB_BEARER_TOKEN" },
    { name: "Cookie", value: "sid=BOB_COOKIE_VALUE" },
    { name: "X-API-Key", value: "BOB_API_KEY_VALUE" },
    { name: "X-CSRF-Token", value: "BOB_CSRF_HEADER" },
    { name: "API-Key", value: "BOB_API_KEY_ALT" },
    { name: "Proxy-Authorization", value: "Basic BOB_PROXY" },
  ],
});

test("isCredentialHeader covers mixed Authorization Cookie API-Key CSRF", () => {
  assert.equal(isCredentialHeader("Authorization"), true);
  assert.equal(isCredentialHeader("Cookie"), true);
  assert.equal(isCredentialHeader("X-API-Key"), true);
  assert.equal(isCredentialHeader("API-Key"), true);
  assert.equal(isCredentialHeader("X-CSRF-Token"), true);
  assert.equal(isCredentialHeader("Proxy-Authorization"), true);
  assert.equal(isCredentialHeader("X-Custom-Auth", ["X-Custom-Auth"]), true);
  assert.equal(isCredentialHeader("Content-Type"), false);
});

test("strip removes every source credential including query and csrf body", () => {
  const { request, strippedNames } = stripSourceCredentials(ALICE);
  const blob = JSON.stringify(request);
  assert.equal(replayHasForeignSecret(blob, ["ALICE_BEARER_TOKEN", "ALICE_COOKIE_VALUE", "ALICE_API_KEY_VALUE", "ALICE_CSRF_HEADER", "ALICE_QUERY_TOKEN", "ALICE_BODY_CSRF"]), false);
  assert.ok(strippedNames.some((n) => /authorization/i.test(n)));
  assert.ok(strippedNames.some((n) => /cookie/i.test(n)));
  assert.ok(strippedNames.some((n) => /api-key/i.test(n)));
  assert.ok(strippedNames.some((n) => /csrf/i.test(n)));
  assert.ok(request.requestHeaders.some((h) => h.name === "Content-Type"));
  assert.doesNotMatch(request.url, /access_token/);
});

test("P0.3 mixed Authorization+Cookie+API-Key+CSRF cannot mix two sessions", () => {
  const creds = extractActorCredentials([BOB]);
  assert.ok(creds);
  const bound = applyCredentialBoundary(ALICE, creds!);
  const curl = curlReplay(bound.request);
  const raw = JSON.stringify(bound.request) + curl;
  const aliceSecrets = [
    "ALICE_BEARER_TOKEN",
    "ALICE_COOKIE_VALUE",
    "ALICE_API_KEY_VALUE",
    "ALICE_CSRF_HEADER",
    "ALICE_QUERY_TOKEN",
    "ALICE_BODY_CSRF",
  ];
  const bobSecrets = [
    "BOB_BEARER_TOKEN",
    "BOB_COOKIE_VALUE",
    "BOB_API_KEY_VALUE",
    "BOB_CSRF_HEADER",
    "BOB_API_KEY_ALT",
    "BOB_PROXY",
  ];
  for (const s of aliceSecrets) {
    assert.equal(raw.includes(s), false, `alice secret leaked: ${s}`);
  }
  for (const s of bobSecrets) {
    assert.equal(raw.includes(s), true, `bob secret missing: ${s}`);
  }
  assert.ok(bound.headerDiff.length >= 4);
  for (const row of bound.headerDiff) {
    assert.doesNotMatch(row.before + row.after, /ALICE_BEARER_TOKEN|ALICE_COOKIE_VALUE|BOB_BEARER_TOKEN|BOB_COOKIE_VALUE/);
  }
  assert.equal(bound.sourceActor, "B");
});

test("workspace extra credential header is wiped then replaced", () => {
  const sample = req({
    actor: "A",
    requestHeaders: [
      { name: "X-Corp-Session", value: "ALICE_CORP" },
      { name: "Authorization", value: "Bearer ALICE_BEARER_TOKEN" },
    ],
  });
  const bob = req({
    actor: "B",
    requestHeaders: [{ name: "X-Corp-Session", value: "BOB_CORP" }],
  });
  const policy = { extraHeaderNames: ["X-Corp-Session"], replaceSecretQueryAndBody: true };
  const creds = extractActorCredentials([bob], policy.extraHeaderNames);
  const bound = applyCredentialBoundary(sample, creds!, policy);
  const blob = JSON.stringify(bound.request);
  assert.equal(blob.includes("ALICE_CORP"), false);
  assert.equal(blob.includes("ALICE_BEARER_TOKEN"), false);
  assert.equal(blob.includes("BOB_CORP"), true);
});

test("desk JSON/MD exporters emit ReportDTO without raw HAR", () => {
  const ws = analyze(demoActorA(), demoActorB(), "alice", "bob");
  const dto = buildReport(ws);
  const json = renderReportJson(dto);
  const md = renderReportMarkdown(dto);
  const parsed = JSON.parse(json) as { schemaVersion: string; aRaw?: string; requests?: unknown; secrets?: string };
  assert.equal(parsed.schemaVersion, "report-dto-1");
  assert.equal("aRaw" in parsed, false);
  assert.equal("bRaw" in parsed, false);
  assert.equal("requests" in parsed, false);
  assert.equal(parsed.aRaw, undefined);
  assert.equal(parsed.requests, undefined);
  assert.equal(parsed.secrets, "redacted");
  assert.match(md, /Secrets: redacted/);
  assert.doesNotMatch(md, /"log":\s*\{/);
});
