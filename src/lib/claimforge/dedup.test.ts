import assert from "node:assert/strict";
import { test } from "node:test";
import { analyze } from "./analyze.ts";
import { jwtIssueKind, mergeFindings } from "./dedup.ts";
import { demoActorA, demoActorB } from "./demo.ts";
import type { Finding } from "./types.ts";

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

function get(t: string, url: string, status: number, token: string, body: object) {
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

test("jwtIssueKind groups none and unsigned", () => {
  assert.equal(jwtIssueKind("alg is none / missing — signature not bound"), "alg-none");
  assert.equal(jwtIssueKind("unsigned (two-part) token"), "alg-none");
});

test("mergeFindings keeps strongest severity and concatenates evidence", () => {
  const a: Finding = {
    id: "F1",
    severity: "critical",
    confidence: "confirmed",
    title: "BOLA A",
    why: "why a",
    evidence: ["e1"],
    how: "how a",
    fingerprint: "bola:/api/invoices/{id}",
  };
  const b: Finding = {
    id: "F2",
    severity: "critical",
    confidence: "confirmed",
    title: "BOLA B",
    why: "why b",
    evidence: ["e2"],
    how: "how b",
    fingerprint: "bola:/api/invoices/{id}",
  };
  const merged = mergeFindings([a, b]);
  assert.equal(merged.length, 1);
  assert.ok(merged[0]!.evidence.includes("e1"));
  assert.ok(merged[0]!.evidence.includes("e2"));
});

test("demo capture has a single confirmed critical BOLA finding", () => {
  const ws = analyze(demoActorA(), demoActorB(), "alice", "bob");
  const bola = ws.findings.filter((f) => f.confidence === "confirmed" && f.severity === "critical" && /BOLA|IDOR/i.test(f.title));
  assert.equal(bola.length, 1, bola.map((f) => f.title).join(" | "));
  const crit = ws.findings.filter((f) => f.severity === "critical").length;
  assert.equal(crit, bola.length);
});

test("ownerId BOLA is not double-counted from diff + stolen-object rules", () => {
  const a = har([
    get("2026-08-29T04:30:00.000Z", "https://shop.lab/api/invoices/5512", 200, jwt("alice"), {
      id: 5512,
      ownerId: "alice",
    }),
  ]);
  const b = har([
    get("2026-08-29T04:30:01.000Z", "https://shop.lab/api/invoices/5512", 200, jwt("bob"), {
      id: 5512,
      ownerId: "alice",
    }),
  ]);
  const ws = analyze(a, b, "alice", "bob");
  const bola = ws.findings.filter((f) => /BOLA|IDOR/i.test(f.title) && f.severity === "critical");
  assert.equal(bola.length, 1);
  assert.ok(bola[0]!.evidence.length >= 2);
  const highOrCrit = ws.findings.filter((f) => f.severity === "critical" || f.severity === "high");
  const fps = highOrCrit.map((f) => f.fingerprint ?? f.title);
  assert.equal(new Set(fps).size, fps.length);
});

test("alg=none and unsigned collapse to one high JWT finding per actor", () => {
  const a = har([get("2026-08-29T07:00:00.000Z", "https://shop.lab/api/me", 200, jwt("alice"), { id: "alice" })]);
  const ws = analyze(a, "", "alice", "bob");
  const jwtHigh = ws.findings.filter((f) => f.severity === "high" && /^JWT/.test(f.title));
  assert.equal(jwtHigh.length, 1);
  assert.match(jwtHigh[0]!.why, /none|unsigned/i);
});
