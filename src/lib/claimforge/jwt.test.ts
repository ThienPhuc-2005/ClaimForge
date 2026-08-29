import assert from "node:assert/strict";
import { test } from "node:test";
import { extractJwtStrings, inspectJwt, mintJwt } from "./jwt.ts";
import { analyze } from "./analyze.ts";
import { demoActorA, demoActorB } from "./demo.ts";

const HS256 = mintJwt(
  { alg: "HS256", typ: "JWT" },
  { sub: "alice", iat: 1_700_000_000, exp: 4_100_000_000 },
  "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
);

const NONE = mintJwt({ alg: "none", typ: "JWT" }, { sub: "bob" });

test("three-part HS256 is not split into a two-part unsigned twin", () => {
  const blob = `Authorization: Bearer ${HS256}\nCookie: sid=1`;
  const found = extractJwtStrings(blob);
  assert.deepEqual(found, [HS256]);
  assert.equal(found[0]?.split(".").length, 3);
  const ins = inspectJwt(found[0]!, "A", "auth");
  assert.equal(ins?.alg, "HS256");
  assert.equal(ins?.parts, 3);
  assert.equal(ins?.sigStatus, "unverified");
  assert.ok((ins?.signature ?? "").length > 0);
  assert.ok(!ins?.issues.some((i) => /unsigned/i.test(i)));
});

test("true missing signature is unsigned, not unverified", () => {
  const two = NONE.replace(/\.$/, "");
  const dotted = NONE;
  for (const raw of [two, dotted]) {
    const found = extractJwtStrings(raw);
    assert.equal(found.length, 1);
    const ins = inspectJwt(found[0]!, "A", "paste");
    assert.equal(ins?.sigStatus, "unsigned");
    assert.equal(ins?.parts, 2);
    assert.equal(ins?.signature, "");
    assert.ok(ins?.issues.some((i) => /unsigned/i.test(i)));
  }
});

test("mixed capture keeps both HS256 and alg=none as distinct tokens", () => {
  const none = NONE.replace(/\.$/, "");
  const found = extractJwtStrings(`${HS256} ${none}`);
  assert.equal(found.length, 2);
  assert.ok(found.includes(HS256));
  assert.ok(found.includes(none));
});

test("analyzer: HS256 → unverified, no unsigned finding", () => {
  const har = JSON.stringify({
    log: {
      entries: [
        {
          startedDateTime: "2026-08-29T03:00:00.000Z",
          request: {
            method: "GET",
            url: "https://lab.local/api/me",
            headers: [{ name: "Authorization", value: `Bearer ${HS256}` }],
          },
          response: { status: 200, headers: [], content: { text: "{\"ok\":true}" } },
        },
      ],
    },
  });
  const ws = analyze(har, "", "alice", "bob");
  assert.equal(ws.jwts.length, 1);
  assert.equal(ws.jwts[0]?.sigStatus, "unverified");
  assert.equal(ws.jwts[0]?.parts, 3);
  assert.ok(!ws.jwts[0]?.issues.some((i) => /unsigned/i.test(i)));
  assert.ok(!ws.findings.some((f) => /unsigned/i.test(f.title) || /unsigned/i.test(f.why)));
});

test("forge mintJwt still emits alg=none with empty third segment", () => {
  const raw = mintJwt({ alg: "none", typ: "JWT" }, { sub: "alice", role: "admin" });
  assert.match(raw, /\.$/);
  const ins = inspectJwt(raw, "A", "forge");
  assert.equal(ins?.alg, "none");
  assert.equal(ins?.sigStatus, "unsigned");
  assert.equal(ins?.payload.role, "admin");
});

test("lab demo: alice none is unsigned; bob HS256 is unverified", () => {
  const ws = analyze(demoActorA(), demoActorB(), "alice", "bob");
  const alice = ws.jwts.filter((j) => j.actor === "A");
  const bob = ws.jwts.filter((j) => j.actor === "B");
  assert.ok(alice.some((j) => j.sigStatus === "unsigned" && j.alg === "none"));
  assert.ok(bob.some((j) => j.sigStatus === "unverified" && String(j.alg).toUpperCase() === "HS256"));
  assert.ok(bob.every((j) => j.sigStatus !== "unsigned"));
  assert.ok(ws.findings.some((f) => /unsigned|alg is none/i.test(f.title + f.why)));
  assert.ok(ws.paths.some((p) => p.id === "path-jwt-none"));
});
