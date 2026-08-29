import assert from "node:assert/strict";
import { test } from "node:test";
import { analyze } from "./analyze.ts";
import { demoActorA, demoActorB } from "./demo.ts";
import { corsCredentialedReadRisk, harvestLoot } from "./loot.ts";
import type { CapturedRequest, Workspace } from "./types.ts";

function har(entries: object[]) {
  return JSON.stringify({ log: { version: "1.2", entries } });
}

function jwt(sub: string, alg: "none" | "HS256" = "none") {
  const header =
    alg === "none"
      ? "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0"
      : "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
  const payload = Buffer.from(JSON.stringify({ sub }), "utf8")
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
  return alg === "none" ? `${header}.${payload}.` : `${header}.${payload}.dummysig`;
}

function get(t: string, url: string, status: number, token: string, body: object, extraReq: Record<string, string> = {}) {
  return {
    startedDateTime: t,
    request: {
      method: "GET",
      url,
      headers: [{ name: "Authorization", value: `Bearer ${token}` }, ...Object.entries(extraReq).map(([name, value]) => ({ name, value }))],
    },
    response: { status, headers: [], content: { text: JSON.stringify(body) } },
  };
}

function confirmedBola(ws: Workspace) {
  return ws.findings.filter((f) => f.confidence === "confirmed" && /BOLA|IDOR/i.test(f.title)).length;
}

type Row = { name: string; ok: boolean; detail: string };

const rows: Row[] = [];

function check(name: string, ok: boolean, detail: string) {
  rows.push({ name, ok, detail });
  assert.ok(ok, `${name}: ${detail}`);
}

test("accuracy benchmark fixtures", () => {
  {
    const a = har([get("2026-08-29T04:00:00.000Z", "https://shop.lab/api/catalog/9", 200, jwt("alice"), { id: 9, visibility: "public" })]);
    const b = har([get("2026-08-29T04:00:01.000Z", "https://shop.lab/api/catalog/9", 200, jwt("bob"), { id: 9, visibility: "public" })]);
    const ws = analyze(a, b, "alice", "bob");
    check("public catalog is not confirmed BOLA", confirmedBola(ws) === 0, `bola=${confirmedBola(ws)}`);
    check("public catalog verdict shared", ws.diffs.some((d) => d.verdict === "shared"), ws.diffs.map((d) => d.verdict).join(","));
  }
  {
    const a = har([get("2026-08-29T04:20:00.000Z", "https://shop.lab/api/items/77", 200, jwt("alice"), { id: 77 })]);
    const b = har([get("2026-08-29T04:20:01.000Z", "https://shop.lab/api/items/77", 200, jwt("bob"), { id: 77 })]);
    const ws = analyze(a, b, "alice", "bob");
    check("same id no owner is suspicion", confirmedBola(ws) === 0 && ws.diffs.some((d) => d.verdict === "suspect"), `bola=${confirmedBola(ws)}`);
  }
  {
    const a = har([get("2026-08-29T04:30:00.000Z", "https://shop.lab/api/invoices/5512", 200, jwt("alice"), { id: 5512, ownerId: "alice" })]);
    const b = har([get("2026-08-29T04:30:01.000Z", "https://shop.lab/api/invoices/5512", 200, jwt("bob"), { id: 5512, ownerId: "alice" })]);
    const ws = analyze(a, b, "alice", "bob");
    check("ownerId + B 2xx is confirmed BOLA", confirmedBola(ws) >= 1, `bola=${confirmedBola(ws)}`);
  }
  {
    const a = har([get("2026-08-29T05:00:00.000Z", "https://shop.lab/api/invoices/5512", 200, jwt("5512", "HS256"), { id: 5512 })]);
    const b = har([get("2026-08-29T05:00:01.000Z", "https://shop.lab/api/invoices/5512", 200, jwt("bob", "HS256"), { id: 5512 })]);
    const ws = analyze(a, b, "alice", "bob");
    check("unverified JWT sub as object id is not confirmed", confirmedBola(ws) === 0, `bola=${confirmedBola(ws)}`);
  }
  {
    const ws = analyze(demoActorA(), demoActorB(), "alice", "bob");
    check("lab demo confirms BOLA", confirmedBola(ws) >= 1, `bola=${confirmedBola(ws)}`);
    check("alg=none stays observation, not confirmed exploit", ws.findings.filter((f) => /none|unsigned/i.test(f.title + f.why)).every((f) => f.confidence !== "confirmed"), "jwt none");
  }
  {
    const dummy: CapturedRequest = {
      id: "c",
      actor: "A",
      startedAt: 1,
      method: "GET",
      url: "https://shop.lab/api/me",
      origin: "https://shop.lab",
      path: "/api/me",
      template: "/api/me",
      query: {},
      requestHeaders: [{ name: "Authorization", value: "Bearer x.y.z" }, { name: "Origin", value: "https://evil.test" }],
      status: 200,
      statusText: "OK",
      responseHeaders: [
        { name: "Access-Control-Allow-Origin", value: "*" },
        { name: "Access-Control-Allow-Credentials", value: "true" },
      ],
      timeMs: 0,
    };
    check("CORS * + credentials is invalid, not credentialed-read loot", corsCredentialedReadRisk("*", "true").kind === "invalid-star-credentials", "cors kind");
    check("CORS * + credentials not harvested as cors loot", harvestLoot([dummy]).every((l) => l.kind !== "cors"), "loot");
  }

  const pass = rows.filter((r) => r.ok).length;
  console.log(`accuracy benchmark ${pass}/${rows.length} fixtures passed`);
  for (const r of rows) console.log(`  ${r.ok ? "ok" : "FAIL"}  ${r.name}  ${r.detail}`);
  assert.equal(pass, rows.length);
});
