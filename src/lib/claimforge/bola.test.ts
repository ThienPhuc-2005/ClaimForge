import assert from "node:assert/strict";
import { test } from "node:test";
import { analyze } from "./analyze.ts";
import { classifySameObject, looksPublicOrShared, sameObjectHits } from "./bola.ts";
import { demoActorA, demoActorB } from "./demo.ts";
import { ownedObjects } from "./ids.ts";
import { MAX_SAME_OBJECT_PAIRS } from "./limits.ts";
import type { CapturedRequest } from "./types.ts";

function har(entries: object[]) {
  return JSON.stringify({ log: { version: "1.2", entries } });
}

function getEntry(
  t: string,
  url: string,
  status: number,
  sub: string,
  body: object,
  alg: "none" | "HS256" = "none",
) {
  const header =
    alg === "none"
      ? "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0"
      : "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
  const payload = Buffer.from(JSON.stringify({ sub }), "utf8")
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
  const token = alg === "none" ? `${header}.${payload}.` : `${header}.${payload}.dummysig`;
  return {
    startedDateTime: t,
    request: {
      method: "GET",
      url,
      headers: [{ name: "Authorization", value: `Bearer ${token}` }],
    },
    response: { status, headers: [], content: { text: JSON.stringify(body) } },
  };
}

test("looksPublicOrShared matches catalog and visibility", () => {
  assert.equal(looksPublicOrShared("/api/catalog/9"), true);
  assert.equal(looksPublicOrShared("/api/invoices/1", [JSON.stringify({ visibility: "public" })]), true);
  assert.equal(looksPublicOrShared("/api/invoices/1", [JSON.stringify({ ownerId: "alice" })]), false);
});

test("public catalog 2xx is observation, never critical BOLA", () => {
  const a = har([
    getEntry("2026-08-29T04:00:00.000Z", "https://shop.lab/api/catalog/9", 200, "alice", {
      id: 9,
      visibility: "public",
      title: "Summer",
    }),
  ]);
  const b = har([
    getEntry("2026-08-29T04:00:01.000Z", "https://shop.lab/api/catalog/9", 200, "bob", {
      id: 9,
      visibility: "public",
      title: "Summer",
    }),
  ]);
  const ws = analyze(a, b, "alice", "bob");
  const row = ws.diffs.find((d) => d.template.includes("/catalog"));
  assert.equal(row?.verdict, "shared");
  assert.ok(!ws.findings.some((f) => f.severity === "critical" && /BOLA/i.test(f.title)));
  assert.ok(ws.findings.some((f) => f.confidence === "observation" && /public|shared/i.test(f.title)));
  assert.ok(!ws.graph.edges.some((e) => e.bola));
});

test("shared members resource is observation", () => {
  const body = { id: 44, shared: true, members: ["alice", "bob"] };
  const a = har([getEntry("2026-08-29T04:10:00.000Z", "https://shop.lab/api/docs/44", 200, "alice", body)]);
  const b = har([getEntry("2026-08-29T04:10:01.000Z", "https://shop.lab/api/docs/44", 200, "bob", body)]);
  const ws = analyze(a, b, "alice", "bob");
  assert.equal(ws.diffs.find((d) => d.template.includes("/docs"))?.verdict, "shared");
  assert.ok(!ws.findings.some((f) => f.confidence === "confirmed" && /BOLA/i.test(f.title)));
});

test("same id without owner proof is suspicion, not critical", () => {
  const a = har([getEntry("2026-08-29T04:20:00.000Z", "https://shop.lab/api/items/77", 200, "alice", { id: 77, name: "x" })]);
  const b = har([getEntry("2026-08-29T04:20:01.000Z", "https://shop.lab/api/items/77", 200, "bob", { id: 77, name: "x" })]);
  const ws = analyze(a, b, "alice", "bob");
  assert.equal(ws.diffs.find((d) => d.template.includes("/items"))?.verdict, "suspect");
  assert.ok(ws.findings.some((f) => f.confidence === "suspicion" && f.severity === "medium"));
  assert.ok(!ws.findings.some((f) => f.severity === "critical" && /items/i.test(f.title)));
});

test("B 2xx on A's ownerId object is confirmed BOLA", () => {
  const a = har([
    getEntry("2026-08-29T04:30:00.000Z", "https://shop.lab/api/invoices/5512", 200, "alice", {
      id: 5512,
      ownerId: "alice",
    }),
  ]);
  const b = har([
    getEntry("2026-08-29T04:30:01.000Z", "https://shop.lab/api/invoices/5512", 200, "bob", {
      id: 5512,
      ownerId: "alice",
      secretLast4: "8211",
    }),
  ]);
  const ws = analyze(a, b, "alice", "bob");
  assert.equal(ws.diffs.find((d) => d.template.includes("/invoices"))?.verdict, "bola");
  assert.ok(ws.findings.some((f) => f.confidence === "confirmed" && f.severity === "critical" && /BOLA/i.test(f.title)));
});

test("lab demo still confirms BOLA on invoice 5512", () => {
  const ws = analyze(demoActorA(), demoActorB(), "alice", "bob");
  assert.ok(ws.findings.some((f) => f.confidence === "confirmed" && f.severity === "critical"));
  assert.ok(ws.paths.some((p) => p.id === "path-horizontal"));
});

test("unverified JWT sub is not treated as an owned object id", () => {
  const a = har([
    getEntry("2026-08-29T05:00:00.000Z", "https://shop.lab/api/invoices/5512", 200, "5512", { id: 5512, name: "x" }, "HS256"),
  ]);
  const b = har([
    getEntry("2026-08-29T05:00:01.000Z", "https://shop.lab/api/invoices/5512", 200, "bob", { id: 5512, name: "x" }, "HS256"),
  ]);
  const ws = analyze(a, b, "alice", "bob");
  assert.ok(!ownedObjects(ws.requests, ws.jwts, "A").has("5512"));
  assert.notEqual(ws.diffs.find((d) => d.template.includes("/invoices"))?.verdict, "bola");
  assert.ok(!ws.findings.some((f) => f.confidence === "confirmed" && /BOLA/i.test(f.title)));
});

test("JWT sub colliding with object id does not confirm BOLA", () => {
  const a = har([
    getEntry("2026-08-29T05:10:00.000Z", "https://shop.lab/api/users/5512", 200, "5512", { id: 5512 }),
    getEntry("2026-08-29T05:10:01.000Z", "https://shop.lab/api/me", 200, "5512", { id: "5512", invoices: [5512] }),
  ]);
  const b = har([getEntry("2026-08-29T05:10:02.000Z", "https://shop.lab/api/users/5512", 200, "bob", { id: 5512 })]);
  const ws = analyze(a, b, "alice", "bob");
  assert.ok(!ownedObjects(ws.requests, ws.jwts, "A").has("5512"));
  assert.ok(!ws.findings.some((f) => f.confidence === "confirmed" && /BOLA/i.test(f.title)));
});

test("classifySameObject units", () => {
  const a = new Set(["5512"]);
  const b = new Set(["8801"]);
  assert.equal(classifySameObject("9", "/api/catalog/9", [], a, b), "observation");
  assert.equal(classifySameObject("5512", "/api/invoices/5512", [JSON.stringify({ ownerId: "alice" })], a, b), "confirmed");
  assert.equal(classifySameObject("77", "/api/items/77", [JSON.stringify({ id: 77 })], a, b), "suspicion");
});

function stubReq(actor: "A" | "B", i: number, path: string): CapturedRequest {
  return {
    id: `${actor}${i}`,
    actor,
    startedAt: i,
    method: "GET",
    url: `https://shop.lab${path}`,
    origin: "https://shop.lab",
    path,
    template: "/api/invoices/{id}",
    query: {},
    requestHeaders: [],
    status: 200,
    statusText: "OK",
    responseHeaders: [],
    timeMs: 0,
  };
}

test("sameObjectHits is path-indexed, capped, and not O(A×B) RAM", () => {
  const a = Array.from({ length: 2000 }, (_, i) => stubReq("A", i, "/api/invoices/1"));
  const b = Array.from({ length: 2000 }, (_, i) => stubReq("B", i, "/api/invoices/1"));
  const before = process.memoryUsage().heapUsed;
  const t0 = performance.now();
  const pairs = sameObjectHits(a, b);
  const dt = performance.now() - t0;
  const used = process.memoryUsage().heapUsed - before;
  assert.equal(pairs.length, MAX_SAME_OBJECT_PAIRS);
  assert.ok(dt < 250, `pairing took ${dt}ms`);
  assert.ok(used < 80 * 1024 * 1024, `pairing used ${used} bytes`);
});
