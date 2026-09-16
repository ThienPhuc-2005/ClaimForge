import assert from "node:assert/strict";
import { test } from "node:test";
import { analyze } from "./analyze.ts";
import { MAX_CAPTURE_BYTES, MAX_REQUESTS_PER_ACTOR } from "./limits.ts";

test("scale caps were raised for larger captures", () => {
  assert.ok(MAX_CAPTURE_BYTES >= 24 * 1024 * 1024, "capture byte cap should be at least 24MB");
  assert.ok(MAX_REQUESTS_PER_ACTOR >= 4000, "per-actor request cap should be at least 4000");
});

function harOf(n: number): string {
  const entries = [];
  for (let i = 0; i < n; i += 1) {
    entries.push({
      startedDateTime: "2026-01-01T00:00:00Z",
      request: { method: "GET", url: `https://shop.lab/items/${i}`, headers: [] },
      response: { status: 200, headers: [], content: { text: "{}" } },
    });
  }
  return JSON.stringify({ log: { entries } });
}

test("truncation beyond the per-actor cap is surfaced, never silent", () => {
  const over = MAX_REQUESTS_PER_ACTOR + 3;
  const ws = analyze(harOf(over), "", "A", "B");
  assert.ok(ws.truncation, "workspace should carry truncation info");
  assert.equal(ws.truncation!.droppedA, 3);
  assert.equal(ws.truncation!.totalA, over);
  assert.equal(ws.truncation!.perActorLimit, MAX_REQUESTS_PER_ACTOR);
  const finding = ws.findings.find((f) => f.reasonCodes.includes("CAPTURE_TRUNCATED"));
  assert.ok(finding, "a CAPTURE_TRUNCATED finding must exist");
});

test("a capture within the cap has no truncation notice", () => {
  const ws = analyze(harOf(5), "", "A", "B");
  assert.equal(ws.truncation, undefined);
  assert.ok(!ws.findings.some((f) => f.reasonCodes.includes("CAPTURE_TRUNCATED")));
});
