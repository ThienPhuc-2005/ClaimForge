import assert from "node:assert/strict";
import { test } from "node:test";
import { analyze } from "./analyze.ts";
import { isIdentifier, isPathIdentifier, ownedObjects, pathIds } from "./ids.ts";
import { templatize } from "./url.ts";

function har(entries: object[]) {
  return JSON.stringify({ log: { version: "1.2", entries } });
}

function getEntry(t: string, url: string, status: number, sub: string, body: object) {
  const header = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0";
  const payload = Buffer.from(JSON.stringify({ sub, userId: sub, email: `${sub}@lab.test` }), "utf8")
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
  const token = `${header}.${payload}.`;
  return {
    startedDateTime: t,
    request: { method: "GET", url, headers: [{ name: "Authorization", value: `Bearer ${token}` }] },
    response: { status, headers: [], content: { text: JSON.stringify(body) } },
  };
}

test("pathIds accepts uuid, ulid, slug with digit, prefixed ids", () => {
  const uuid = "550e8400-e29b-41d4-a716-446655440000";
  const ulid = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
  assert.deepEqual(pathIds(`/api/invoices/${uuid}`), [uuid]);
  assert.deepEqual(pathIds(`/api/orders/${ulid}`), [ulid]);
  assert.deepEqual(pathIds("/api/invoices/inv_A84KL2"), ["inv_A84KL2"]);
  assert.deepEqual(pathIds("/api/posts/summer-sale-2024"), ["summer-sale-2024"]);
  assert.ok(isPathIdentifier("inv_A84KL2"));
  assert.ok(isIdentifier(uuid));
  assert.ok(isIdentifier(ulid));
});

test("pathIds negatives: route words, versions, years, hello-world slug", () => {
  assert.deepEqual(pathIds("/api/v2/invoices"), []);
  assert.deepEqual(pathIds("/api/users"), []);
  assert.deepEqual(pathIds("/api/reports/2024"), []);
  assert.deepEqual(pathIds("/api/posts/hello-world"), []);
  assert.equal(isPathIdentifier("invoices"), false);
  assert.equal(isPathIdentifier("v2"), false);
  assert.equal(isPathIdentifier("catalog"), false);
});

test("templatize maps new id shapes", () => {
  assert.equal(templatize("/api/invoices/inv_A84KL2"), "/api/invoices/{id}");
  assert.equal(
    templatize("/api/invoices/550e8400-e29b-41d4-a716-446655440000"),
    "/api/invoices/{uuid}",
  );
  assert.equal(templatize("/api/orders/01ARZ3NDEKTSV4RRFFQ69G5FAV"), "/api/orders/{ulid}");
  assert.equal(templatize("/api/posts/summer-sale-2024"), "/api/posts/{slug}");
});

test("BOLA confirmed on prefixed invoice id with JWT userId identity", () => {
  const a = har([
    getEntry("2026-08-29T06:00:00.000Z", "https://shop.lab/api/invoices/inv_A84KL2", 200, "alice", {
      id: "inv_A84KL2",
      ownerId: "alice",
    }),
  ]);
  const b = har([
    getEntry("2026-08-29T06:00:01.000Z", "https://shop.lab/api/invoices/inv_A84KL2", 200, "bob", {
      id: "inv_A84KL2",
      ownerId: "alice",
    }),
  ]);
  const ws = analyze(a, b, "alice", "bob");
  assert.ok(ownedObjects(ws.requests, ws.jwts, "A").has("inv_A84KL2"));
  assert.ok(ws.findings.some((f) => f.confidence === "confirmed" && /BOLA/i.test(f.title)));
  assert.equal(ws.diffs.find((d) => d.template.includes("/invoices"))?.verdict, "bola");
});

test("BOLA confirmed on UUID object with owner userId matching JWT sub", () => {
  const id = "550e8400-e29b-41d4-a716-446655440000";
  const a = har([
    getEntry("2026-08-29T06:10:00.000Z", `https://shop.lab/api/files/${id}`, 200, "alice", {
      id,
      userId: "alice",
    }),
  ]);
  const b = har([
    getEntry("2026-08-29T06:10:01.000Z", `https://shop.lab/api/files/${id}`, 200, "bob", { id, userId: "alice" }),
  ]);
  const ws = analyze(a, b, "alice", "bob");
  assert.ok(ws.findings.some((f) => f.confidence === "confirmed" && /BOLA/i.test(f.title)));
});

test("both 2xx on /api/v2/invoices is not an object pair (no path id)", () => {
  const a = har([
    getEntry("2026-08-29T06:20:00.000Z", "https://shop.lab/api/v2/invoices", 200, "alice", { items: [] }),
  ]);
  const b = har([
    getEntry("2026-08-29T06:20:01.000Z", "https://shop.lab/api/v2/invoices", 200, "bob", { items: [] }),
  ]);
  const ws = analyze(a, b, "alice", "bob");
  assert.ok(!ws.findings.some((f) => f.confidence === "confirmed" && /BOLA/i.test(f.title)));
});
