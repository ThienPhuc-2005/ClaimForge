import assert from "node:assert/strict";
import { test } from "node:test";
import { redactJwt, redactText, redactWorkspace } from "./redact.ts";
import { analyze } from "./analyze.ts";
import { demoActorA, demoActorB } from "./demo.ts";

test("export redacts JWT signature and bearer", () => {
  const raw = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhIn0.supersecret";
  assert.equal(redactJwt(raw), "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhIn0.[sig]");
  assert.match(redactText(`Authorization: Bearer ${raw}`), /\[redacted\]|\[sig\]/);
});

test("workspace export drops raw captures and cookie values", () => {
  const ws = analyze(demoActorA(), demoActorB(), "alice", "bob");
  const safe = redactWorkspace(ws);
  assert.equal(safe.aRaw, "");
  assert.equal(safe.bRaw, "");
  assert.ok(safe.cookies.every((c) => c.value === "••••" || c.value.includes("…") || c.value === "[redacted]"));
  assert.ok(!JSON.stringify(safe.jwts).includes("dummysig"));
});
