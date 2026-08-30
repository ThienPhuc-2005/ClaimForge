import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { analyze } from "./analyze.ts";
import { demoActorA, demoActorB } from "./demo.ts";
import { fetchJwksDocument } from "./jwks-fetch.ts";
import { P0_GATES, P0_ITEMS } from "./p0-gates.ts";
import { applyCredentialBoundary, extractActorCredentials } from "./replay-credentials.ts";
import { buildReport, renderReportJson, renderReportMarkdown } from "./report.ts";
import type { CapturedRequest } from "./types.ts";

const here = dirname(fileURLToPath(import.meta.url));

function har(entries: object[]) {
  return JSON.stringify({ log: { version: "1.2", entries } });
}

function jwt(sub: string) {
  const header = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0";
  const payload = Buffer.from(JSON.stringify({ sub }), "utf8")
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
  return `${header}.${payload}.`;
}

function get(t: string, url: string, status: number, sub: string, body: object, headers: { name: string; value: string }[] = []) {
  return {
    startedDateTime: t,
    request: {
      method: "GET",
      url,
      headers: [{ name: "Authorization", value: `Bearer ${jwt(sub)}` }, ...headers],
    },
    response: { status, headers: [], content: { text: JSON.stringify(body) } },
  };
}

function req(partial: Partial<CapturedRequest>): CapturedRequest {
  return {
    id: "t",
    actor: "A",
    startedAt: 1,
    method: "GET",
    url: "https://shop.lab/x",
    origin: "https://shop.lab",
    path: "/x",
    template: "/x",
    query: {},
    requestHeaders: [],
    status: 200,
    statusText: "OK",
    responseHeaders: [],
    timeMs: 0,
    ...partial,
  };
}

test("P0.8 catalog covers every P0.1–P0.7 item with unique ids", () => {
  const ids = P0_GATES.map((g) => g.id);
  assert.equal(ids.length, new Set(ids).size);
  for (const item of P0_ITEMS) {
    const n = P0_GATES.filter((g) => g.p0 === item).length;
    assert.ok(n >= 1, `missing adversarial gate for ${item}`);
  }
});

test("P0.8 every gate points at a test file that exists", () => {
  for (const g of P0_GATES) {
    const file = g.evidenceTest.split(":")[0]!;
    assert.ok(existsSync(join(here, file)), `${g.id} missing ${file}`);
    assert.ok(g.before.length > 8 && g.after.length > 8, g.id);
  }
});

test("GATE P0.1 path segment is not ownership (would fail before fix)", () => {
  const a = har([
    get("2026-08-30T02:00:00.000Z", "https://shop.lab/api/users/alice/invoices/77", 200, "alice", { id: 77, title: "q" }),
  ]);
  const b = har([
    get("2026-08-30T02:00:01.000Z", "https://shop.lab/api/users/alice/invoices/77", 200, "bob", { id: 77, title: "q" }),
  ]);
  const ws = analyze(a, b, "alice", "bob");
  const confirmed = ws.findings.filter((f) => f.confidence === "confirmed" && /BOLA|IDOR/i.test(f.title));
  assert.equal(confirmed.length, 0);
  assert.ok(!ws.findings.some((f) => f.severity === "critical" && /BOLA|IDOR/i.test(f.title)));
});

test("GATE P0.2 wordlist formulas are neutralized in markdown (would fail before fix)", () => {
  const ws = analyze(demoActorA(), demoActorB(), "alice", "bob");
  ws.wordlists.ids = ["=HYPERLINK(\"http://evil.example\")", "+cmd|' /C calc'!A0", "@SUM(1+1)", "5512"];
  const md = renderReportMarkdown(buildReport(ws));
  assert.match(md, /'=HYPERLINK/);
  assert.match(md, /'\+cmd/);
  assert.match(md, /'@SUM/);
  assert.doesNotMatch(md, /\n=HYPERLINK/);
  assert.doesNotMatch(md, /\n\+cmd/);
  assert.doesNotMatch(md, /\n@SUM/);
});

test("GATE P0.2 compact JWT in evidence does not survive JSON (would fail before fix)", () => {
  const compact = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJjYW5hcnkifQ.supersecretSIG";
  const ws = analyze(demoActorA(), demoActorB(), "alice", "bob");
  ws.findings = [
    {
      ...ws.findings[0]!,
      id: "JWT-CANARY",
      why: compact,
      evidence: [compact, `Bearer ${compact}`],
    },
  ];
  const json = renderReportJson(buildReport(ws));
  assert.doesNotMatch(json, /supersecretSIG/);
  assert.doesNotMatch(json, /eyJhbGciOiJIUzI1NiJ9\.eyJzdWIiOiJjYW5hcnkifQ/);
});

test("GATE P0.3 query token is not mixed into the other actor replay (would fail before fix)", () => {
  const alice = req({
    actor: "A",
    url: "https://shop.lab/api/invoices/5512?access_token=ALICE_QUERY_TOKEN",
    path: "/api/invoices/5512",
    query: { access_token: "ALICE_QUERY_TOKEN" },
    requestHeaders: [
      { name: "Authorization", value: "Bearer ALICE_BEARER" },
      { name: "Cookie", value: "sid=ALICE_COOKIE" },
    ],
  });
  const bob = req({
    actor: "B",
    requestHeaders: [
      { name: "Authorization", value: "Bearer BOB_BEARER" },
      { name: "Cookie", value: "sid=BOB_COOKIE" },
    ],
  });
  const bound = applyCredentialBoundary(alice, extractActorCredentials([bob])!);
  const blob = JSON.stringify(bound.request);
  assert.equal(blob.includes("ALICE_QUERY_TOKEN"), false);
  assert.equal(blob.includes("ALICE_BEARER"), false);
  assert.equal(blob.includes("ALICE_COOKIE"), false);
  assert.equal(blob.includes("BOB_BEARER"), true);
  assert.doesNotMatch(bound.request.url, /access_token/);
});

test("GATE P0.6 fetch omits credentials and does not follow redirects (would fail before fix)", async () => {
  let init: RequestInit | undefined;
  const fetchImpl = (async (_input: RequestInfo | URL, i?: RequestInit) => {
    init = i;
    return new Response(JSON.stringify({ keys: [] }), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  }) as typeof fetch;
  await fetchJwksDocument("https://issuer.example/jwks", { confirmed: true, fetchImpl });
  assert.equal(init?.credentials, "omit");
  assert.equal(init?.redirect, "manual");
  assert.equal(init?.method, "GET");
});

test("GATE P0.6 audit must not contain JWK material (would fail before fix)", async () => {
  const n = "modulus-secret-value-do-not-log";
  const fetchImpl = (async () =>
    new Response(JSON.stringify({ keys: [{ kty: "RSA", kid: "k1", n, e: "AQAB" }] }), {
      status: 200,
      headers: { "content-type": "application/json" },
    })) as typeof fetch;
  const { jwks, audit } = await fetchJwksDocument("https://issuer.example/jwks", { confirmed: true, fetchImpl });
  assert.equal(jwks.keys.length, 1);
  const dumped = JSON.stringify(audit);
  assert.doesNotMatch(dumped, /modulus-secret-value-do-not-log/);
  assert.doesNotMatch(dumped, /"n"/);
  assert.doesNotMatch(dumped, /AQAB/);
  assert.doesNotMatch(dumped, /kty/);
  assert.equal(audit.hostname, "issuer.example");
  assert.equal(audit.result, "ok");
});

test("GATE P0.7 CORS star+credentials is not Confirmed Critical (would fail before fix)", () => {
  const a = har([
    {
      startedDateTime: "2026-08-30T02:10:00.000Z",
      request: {
        method: "GET",
        url: "https://shop.lab/api/me",
        headers: [{ name: "Authorization", value: `Bearer ${jwt("alice")}` }],
      },
      response: {
        status: 200,
        headers: [
          { name: "Access-Control-Allow-Origin", value: "*" },
          { name: "Access-Control-Allow-Credentials", value: "true" },
        ],
        content: { text: JSON.stringify({ id: "alice" }) },
      },
    },
  ]);
  const ws = analyze(a, "", "alice", "bob");
  const cors = ws.findings.filter(
    (f) =>
      /cors/i.test(f.title) ||
      f.reasonCodes.includes("CORS_STAR_NO_CREDENTIALS") ||
      f.reasonCodes.includes("CORS_REFLECTED_CREDENTIALS"),
  );
  assert.ok(!cors.some((f) => f.confidence === "confirmed"));
  assert.ok(!cors.some((f) => f.severity === "critical"));
});
