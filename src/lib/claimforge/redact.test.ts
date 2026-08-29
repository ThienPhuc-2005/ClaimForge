import assert from "node:assert/strict";
import { test } from "node:test";
import { redactJwt, redactText, redactWorkspace } from "./redact.ts";
import { analyze } from "./analyze.ts";
import { demoActorA, demoActorB } from "./demo.ts";
import { exportReportJson, engagementMarkdown } from "./report.ts";

test("export redacts JWT signature and bearer", () => {
  const raw = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhIn0.supersecret";
  assert.equal(redactJwt(raw), "eyJhbGciOiJIUzI1NiJ9.[payload].[sig]");
  assert.match(redactText(`Authorization: Bearer ${raw}`), /\[redacted\]|\[payload\]/);
});

test("redactText masks passwords, cookies, and query tokens", () => {
  assert.match(redactText('{"password":"demo","token":"abc"}'), /\[redacted\]/);
  assert.doesNotMatch(redactText('{"password":"demo"}'), /"demo"/);
  assert.match(redactText("Cookie: sid=alice-session-01; Path=/"), /\[redacted\]/);
  assert.doesNotMatch(redactText("Cookie: sid=alice-session-01"), /alice-session-01/);
  assert.match(redactText("https://x/api?access_token=eyJhbGciOiJub25lIn0.eyJzdWIiOiJhIn0."), /\[redacted\]/);
});

test("workspace export drops raw captures and cookie values", () => {
  const ws = analyze(demoActorA(), demoActorB(), "alice", "bob");
  const safe = redactWorkspace(ws);
  assert.equal(safe.aRaw, "");
  assert.equal(safe.bRaw, "");
  assert.ok(safe.cookies.every((c) => c.value === "••••" || c.value.includes("…") || c.value === "[redacted]"));
  assert.ok(!JSON.stringify(safe.jwts).includes("dummysig"));
});

test("export JSON and markdown do not leak tokens, cookies, or passwords from diffs/findings", () => {
  const ws = analyze(demoActorA(), demoActorB(), "alice", "bob");
  const json = JSON.stringify(exportReportJson(ws));
  const md = engagementMarkdown(ws);
  for (const blob of [json, md]) {
    assert.doesNotMatch(blob, /dummysig/);
    assert.doesNotMatch(blob, /alice-session-01/);
    assert.doesNotMatch(blob, /"password"\s*:\s*"demo"/i);
    assert.doesNotMatch(blob, /Bearer eyJ/);
    assert.doesNotMatch(blob, /sid=alice-session/);
    assert.doesNotMatch(blob, /supersecret/);
  }
  const parsed = exportReportJson(ws);
  for (const d of parsed.diffs) {
    const sample = JSON.stringify({ a: d.aSample, b: d.bSample });
    assert.doesNotMatch(sample, /alice-session-01/);
    assert.doesNotMatch(sample, /dummysig/);
    assert.doesNotMatch(sample, /"password"\s*:\s*"demo"/);
    for (const h of [...(d.aSample?.requestHeaders ?? []), ...(d.bSample?.requestHeaders ?? [])]) {
      if (/authorization|cookie|password/i.test(h.name)) assert.equal(h.value, "[redacted]");
    }
  }
  for (const f of parsed.findings) {
    const blob = `${f.title}\n${f.why}\n${f.how}\n${f.evidence.join("\n")}`;
    assert.doesNotMatch(blob, /dummysig/);
    assert.doesNotMatch(blob, /alice-session-01/);
    assert.doesNotMatch(blob, /Bearer eyJ/);
  }
});
