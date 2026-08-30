import assert from "node:assert/strict";
import { test } from "node:test";
import { buildReplays, curlReplay } from "./playbook.ts";
import { analyze } from "./analyze.ts";
import { demoActorA, demoActorB } from "./demo.ts";
import type { CapturedRequest } from "./types.ts";
import { credentialSetFromBearer } from "./replay-credentials.ts";

test("curl replay keeps method and body, no -k", () => {
  const sample: CapturedRequest = {
    id: "1",
    actor: "A",
    startedAt: 1,
    method: "PATCH",
    url: "https://shop.lab/api/users/me",
    origin: "https://shop.lab",
    path: "/api/users/me",
    template: "/api/users/me",
    query: {},
    requestHeaders: [
      { name: "Content-Type", value: "application/json" },
      { name: "Authorization", value: "Bearer old" },
      { name: "Cookie", value: "sid=alice-session-01" },
    ],
    requestBody: '{"role":"admin"}',
    status: 200,
    statusText: "OK",
    responseHeaders: [],
    timeMs: 0,
  };
  const c = curlReplay(sample, credentialSetFromBearer("B", "newtok"));
  assert.match(c, /curl -sS/);
  assert.doesNotMatch(c, /(^|\s)-k(\s|$)/);
  assert.match(c, /-X PATCH/);
  assert.match(c, /--data-binary/);
  assert.match(c, /role/);
  assert.match(c, /Bearer newtok/);
  assert.doesNotMatch(c, /alice-session-01/);
  assert.doesNotMatch(c, /Bearer old/);
});

test("BOLA / swap replays strip the other actor's credentials", () => {
  const ws = analyze(demoActorA(), demoActorB(), "alice", "bob");
  const replays = ws.replays.length ? ws.replays : buildReplays(ws);
  assert.ok(replays.length > 0);
  for (const r of replays) {
    assert.doesNotMatch(r.curl, /alice-session-01/);
    assert.doesNotMatch(r.raw, /alice-session-01/);
    if (/BOLA|Hypothesis/i.test(r.title)) {
      assert.ok(r.credentialSource);
      assert.equal(r.credentialSource?.actor, "B");
    }
  }
});
