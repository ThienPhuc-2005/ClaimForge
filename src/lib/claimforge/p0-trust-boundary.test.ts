import assert from "node:assert/strict";
import { test } from "node:test";
import { analyze } from "./analyze.ts";
import { ownedObjects, trustedIdentities } from "./ids.ts";
import { DEFAULT_POLICY } from "./policy.ts";
import { ENGINE_VERSION, RULE_VERSION } from "./versions.ts";

function har(entries: object[]) {
  return JSON.stringify({ log: { version: "1.2", entries } });
}

function jwtParts(sub: string, alg: "none" | "HS256" = "none") {
  const header =
    alg === "none"
      ? "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0"
      : "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
  const payload = Buffer.from(JSON.stringify({ sub, userId: sub }), "utf8")
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
  return alg === "none" ? `${header}.${payload}.` : `${header}.${payload}.dummysig`;
}

function entry(opts: {
  t: string;
  url: string;
  status: number;
  sub: string;
  response?: object;
  requestBody?: object;
  method?: string;
  queryAuth?: boolean;
  alg?: "none" | "HS256";
}) {
  const token = jwtParts(opts.sub, opts.alg ?? "none");
  const url = opts.url;
  return {
    startedDateTime: opts.t,
    request: {
      method: opts.method ?? "GET",
      url,
      headers: [{ name: "Authorization", value: `Bearer ${token}` }],
      queryString: url.includes("?")
        ? url
            .split("?")[1]!
            .split("&")
            .map((p) => {
              const [n, v] = p.split("=");
              return { name: n, value: v };
            })
        : [],
      postData: opts.requestBody ? { text: JSON.stringify(opts.requestBody) } : undefined,
    },
    response: {
      status: opts.status,
      headers: [],
      content: { text: JSON.stringify(opts.response ?? {}) },
    },
  };
}

function confirmedBola(ws: ReturnType<typeof analyze>) {
  return ws.findings.filter((f) => f.confidence === "confirmed" && /BOLA|IDOR/i.test(f.title));
}

test("P0.1 analysis envelope is deterministic", () => {
  const a = har([
    entry({
      t: "2026-08-30T00:00:00.000Z",
      url: "https://shop.lab/api/invoices/5512",
      status: 200,
      sub: "alice",
      response: { id: 5512, ownerId: "alice" },
    }),
  ]);
  const b = har([
    entry({
      t: "2026-08-30T00:00:01.000Z",
      url: "https://shop.lab/api/invoices/5512",
      status: 200,
      sub: "bob",
      response: { id: 5512, ownerId: "alice" },
    }),
  ]);
  const x = analyze(a, b, "alice", "bob");
  const y = analyze(a, b, "alice", "bob");
  assert.equal(x.engineVersion, ENGINE_VERSION);
  assert.equal(x.ruleVersion, RULE_VERSION);
  assert.equal(x.policyVersion, DEFAULT_POLICY.version);
  assert.equal(x.inputHash, y.inputHash);
  assert.equal(x.resultHash, y.resultHash);
  assert.ok(confirmedBola(x).length >= 1);
  assert.ok(confirmedBola(x)[0]!.canonical?.ownershipTrusted);
  assert.ok(confirmedBola(x)[0]!.reasonCodes?.includes("SERVER_OWNERSHIP_PROOF"));
});

test("request body ownerId cannot create confirmed BOLA", () => {
  const a = har([
    entry({
      t: "2026-08-30T01:00:00.000Z",
      url: "https://shop.lab/api/invoices/5512",
      status: 200,
      sub: "alice",
      method: "POST",
      requestBody: { id: 5512, ownerId: "alice" },
      response: { id: 5512, name: "client-asserted" },
    }),
  ]);
  const b = har([
    entry({
      t: "2026-08-30T01:00:01.000Z",
      url: "https://shop.lab/api/invoices/5512",
      status: 200,
      sub: "bob",
      method: "POST",
      requestBody: { id: 5512, ownerId: "alice" },
      response: { id: 5512, name: "client-asserted" },
    }),
  ]);
  const ws = analyze(a, b, "alice", "bob");
  assert.equal(ownedObjects(ws.requests, ws.jwts, "A", ws.cookies, { declaredLabel: "alice" }).has("5512"), false);
  assert.equal(confirmedBola(ws).length, 0);
  assert.ok(
    ws.findings.some((f) => f.confidence === "suspicion") ||
      ws.diffs.some((d) => d.verdict === "suspect" || d.verdict === "same" || d.verdict === "mixed"),
  );
});

test("request query ownerId cannot create confirmed BOLA", () => {
  const a = har([
    entry({
      t: "2026-08-30T01:10:00.000Z",
      url: "https://shop.lab/api/invoices/5512?ownerId=alice",
      status: 200,
      sub: "alice",
      response: { id: 5512, title: "q" },
    }),
  ]);
  const b = har([
    entry({
      t: "2026-08-30T01:10:01.000Z",
      url: "https://shop.lab/api/invoices/5512?ownerId=alice",
      status: 200,
      sub: "bob",
      response: { id: 5512, title: "q" },
    }),
  ]);
  const ws = analyze(a, b, "alice", "bob");
  assert.equal(confirmedBola(ws).length, 0);
});

test("unverified JWT sub is not a trusted identity", () => {
  const ids = trustedIdentities(
    [
      {
        actor: "A",
        raw: jwtParts("alice", "HS256"),
        source: "test",
        header: { alg: "HS256" },
        payload: { sub: "alice" },
        alg: "HS256",
        parts: 3,
        signature: "dummysig",
        sigStatus: "unverified",
        issues: [],
      },
    ],
    "A",
    { declaredLabel: "" },
  );
  assert.equal(ids.size, 0);
});

test("unverified JWT sub colliding with object id cannot confirm BOLA", () => {
  const a = har([
    entry({
      t: "2026-08-30T01:20:00.000Z",
      url: "https://shop.lab/api/invoices/5512",
      status: 200,
      sub: "5512",
      alg: "HS256",
      response: { id: 5512, name: "x" },
    }),
  ]);
  const b = har([
    entry({
      t: "2026-08-30T01:20:01.000Z",
      url: "https://shop.lab/api/invoices/5512",
      status: 200,
      sub: "bob",
      alg: "HS256",
      response: { id: 5512, name: "x" },
    }),
  ]);
  const ws = analyze(a, b, "victim", "attacker");
  assert.ok(!ownedObjects(ws.requests, ws.jwts, "A", ws.cookies, { declaredLabel: "victim" }).has("5512"));
  assert.equal(confirmedBola(ws).length, 0);
});

test("response ownerId + analyst map still confirms BOLA", () => {
  const a = har([
    entry({
      t: "2026-08-30T01:30:00.000Z",
      url: "https://shop.lab/api/invoices/5512",
      status: 200,
      sub: "alice",
      response: { id: 5512, ownerId: "alice" },
    }),
  ]);
  const b = har([
    entry({
      t: "2026-08-30T01:30:01.000Z",
      url: "https://shop.lab/api/invoices/5512",
      status: 200,
      sub: "bob",
      response: { id: 5512, ownerId: "alice", secretLast4: "8211" },
    }),
  ]);
  const ws = analyze(a, b, "alice", "bob");
  assert.ok(confirmedBola(ws).length >= 1);
});
