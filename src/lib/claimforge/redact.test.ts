import assert from "node:assert/strict";
import { test } from "node:test";
import { maskSecret, redactJsonValue, redactJwt, redactText, redactWorkspace } from "./redact.ts";
import { analyze } from "./analyze.ts";
import { demoActorA, demoActorB } from "./demo.ts";
import { exportReportJson, engagementMarkdown } from "./report.ts";

test("export redacts JWT signature and bearer", () => {
  const raw = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhIn0.supersecret";
  assert.equal(redactJwt(raw), "eyJhbGciOiJIUzI1NiJ9.[payload].[sig]");
  assert.match(redactText(`Authorization: Bearer ${raw}`), /\[redacted\]|\[payload\]/);
});

test("maskSecret never leaks prefix or suffix", () => {
  const v = "sk_live_supersecretvalue99";
  assert.equal(maskSecret(v), "[redacted]");
  assert.doesNotMatch(maskSecret(v), /sk_l/);
  assert.doesNotMatch(maskSecret(v), /99/);
});

test("redactText masks passwords, cookies, and query tokens", () => {
  assert.match(redactText('{"password":"demo","token":"abc"}'), /\[redacted\]/);
  assert.doesNotMatch(redactText('{"password":"demo"}'), /"demo"/);
  assert.match(redactText("Cookie: sid=alice-session-01; Path=/"), /\[redacted\]/);
  assert.doesNotMatch(redactText("Cookie: sid=alice-session-01"), /alice-session-01/);
  assert.match(redactText("https://x/api?access_token=eyJhbGciOiJub25lIn0.eyJzdWIiOiJhIn0."), /\[redacted\]/);
});

test("recursive JSON redaction covers nested secret key variants", () => {
  const nested = {
    user: {
      password: "demo-pass",
      clientSecret: "cs_live_abc",
      apiKey: "ak_1234567890",
      private_key: "-----BEGIN PRIVATE KEY-----\nMII\n-----END PRIVATE KEY-----",
      authorization: "Bearer supersecret",
      cookie: "sid=alice-session-01",
      token: "refresh-me",
      profile: { name: "alice" },
    },
  };
  const out = JSON.stringify(redactJsonValue(nested));
  for (const leak of ["demo-pass", "cs_live_abc", "ak_1234567890", "MII", "supersecret", "alice-session-01", "refresh-me"]) {
    assert.doesNotMatch(out, new RegExp(leak));
  }
  assert.match(out, /"name":"alice"/);
  assert.match(out, /\[redacted\]/);
});

test("redactText JSON blob does not leak nested credentials", () => {
  const blob = JSON.stringify({
    auth: { client_secret: "shh-dont", api_key: "k-99" },
    ok: true,
  });
  const red = redactText(blob);
  assert.doesNotMatch(red, /shh-dont/);
  assert.doesNotMatch(red, /k-99/);
  assert.match(red, /\[redacted\]/);
});

test("adversarial plaintext does not leak PEM or cookie values", () => {
  const pem = "-----BEGIN RSA PRIVATE KEY-----\nABCDEF123\n-----END RSA PRIVATE KEY-----";
  const red = redactText(`key=${pem}\nCookie: sid=alice-session-01`);
  assert.doesNotMatch(red, /ABCDEF123/);
  assert.doesNotMatch(red, /alice-session-01/);
});

test("workspace export drops raw captures and cookie values", () => {
  const ws = analyze(demoActorA(), demoActorB(), "alice", "bob");
  const safe = redactWorkspace(ws);
  assert.equal(safe.aRaw, "");
  assert.equal(safe.bRaw, "");
  assert.ok(safe.cookies.every((c) => c.value === "[redacted]"));
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
  assert.equal("aSample" in (parsed.diffs[0] ?? {}), false);
  for (const f of parsed.findings) {
    const blob = `${f.title}\n${f.why}\n${f.how}\n${f.evidence.join("\n")}`;
    assert.doesNotMatch(blob, /dummysig/);
    assert.doesNotMatch(blob, /alice-session-01/);
    assert.doesNotMatch(blob, /Bearer eyJ/);
  }
});
