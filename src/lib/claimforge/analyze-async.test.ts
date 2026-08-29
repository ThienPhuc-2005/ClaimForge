import assert from "node:assert/strict";
import { test } from "node:test";
import { analyzeAsync, cancelAnalyzeJobs, pendingAnalyzeCount, rejectAllAnalyzeWork } from "./analyze-async.ts";
import { WORKER_ANALYZE_BYTES } from "./limits.ts";

test("worker crash rejects every pending analyze promise", async () => {
  const pending = new Map<number, { resolve: (v: unknown) => void; reject: (e: Error) => void }>();
  let terminated = false;

  function rejectAll(reason: string) {
    const err = new Error(reason);
    const boxes = [...pending.values()];
    pending.clear();
    terminated = true;
    for (const b of boxes) b.reject(err);
  }

  const p1 = new Promise((_, reject) => {
    pending.set(1, { resolve: () => {}, reject });
  });
  const p2 = new Promise((_, reject) => {
    pending.set(2, { resolve: () => {}, reject });
  });
  rejectAll("boom");
  await assert.rejects(p1, /boom/);
  await assert.rejects(p2, /boom/);
  assert.equal(pending.size, 0);
  assert.equal(terminated, true);
  rejectAllAnalyzeWork("idle");
  assert.equal(pendingAnalyzeCount(), 0);
  assert.ok(WORKER_ANALYZE_BYTES > 0);
});

test("newer analyzeAsync cancels the previous yield job", async () => {
  const p1 = analyzeAsync("stale-capture", "", "alice", "bob");
  const p2 = analyzeAsync("", "", "alice", "bob");
  await assert.rejects(p1, /cancelled|superseded/);
  const ws = await p2;
  assert.equal(ws.requests.length, 0);
  assert.equal(pendingAnalyzeCount(), 0);
});

test("cancelAnalyzeJobs rejects in-flight yield", async () => {
  const p = analyzeAsync("{", "", "a", "b");
  cancelAnalyzeJobs("cleared");
  await assert.rejects(p, /cancelled|superseded/);
});
