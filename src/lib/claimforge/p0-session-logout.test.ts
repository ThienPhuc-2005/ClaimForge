import assert from "node:assert/strict";
import { test } from "node:test";
import { analyze } from "./analyze.ts";
import { isLogoutAnalysisTarget, tokensAliveAfterLogout } from "./session.ts";
import type { CapturedRequest } from "./types.ts";

function har(entries: object[]) {
  return JSON.stringify({ log: { version: "1.2", entries } });
}

function entry(
  t: string,
  method: string,
  url: string,
  status: number,
  headers: { name: string; value: string }[] = [],
) {
  return {
    startedDateTime: t,
    request: { method, url, headers },
    response: { status, headers: [], content: { text: "{}" } },
  };
}

function req(p: Partial<CapturedRequest> & Pick<CapturedRequest, "path" | "method">): CapturedRequest {
  return {
    id: "x",
    actor: "A",
    startedAt: 1,
    url: `https://shop.lab${p.path}`,
    origin: "https://shop.lab",
    template: p.path,
    query: {},
    requestHeaders: [],
    status: 200,
    statusText: "OK",
    responseHeaders: [],
    timeMs: 0,
    ...p,
  };
}

test("logout one session; sibling bearer+cookie still valid is not a finding for the sibling", () => {
  const raw = har([
    entry("2026-08-30T01:00:00.000Z", "GET", "https://shop.lab/api/me", 200, [
      { name: "Authorization", value: "Bearer TOK_DEVICE_A" },
      { name: "Cookie", value: "sid=SID_A; theme=dark" },
    ]),
    entry("2026-08-30T01:00:01.000Z", "GET", "https://shop.lab/api/me", 200, [
      { name: "Authorization", value: "Bearer TOK_DEVICE_B" },
      { name: "Cookie", value: "sid=SID_B" },
    ]),
    entry("2026-08-30T01:00:02.000Z", "POST", "https://shop.lab/api/logout", 200, [
      { name: "Authorization", value: "Bearer TOK_DEVICE_A" },
      { name: "Cookie", value: "sid=SID_A" },
    ]),
    entry("2026-08-30T01:00:03.000Z", "GET", "https://shop.lab/api/me", 200, [
      { name: "Authorization", value: "Bearer TOK_DEVICE_A" },
      { name: "Cookie", value: "sid=SID_A" },
    ]),
    entry("2026-08-30T01:00:04.000Z", "GET", "https://shop.lab/api/me", 200, [
      { name: "Authorization", value: "Bearer TOK_DEVICE_B" },
      { name: "Cookie", value: "sid=SID_B" },
    ]),
  ]);
  const ws = analyze(raw, "", "alice", "bob");
  const hits = tokensAliveAfterLogout(ws.requests, ws.policy);
  assert.ok(hits.some((h) => h.credentialId.includes("TOK_DEVICE_A") || h.credentialId.includes("SID_A")));
  assert.equal(
    hits.some((h) => h.credentialId.includes("TOK_DEVICE_B") || h.credentialId.includes("SID_B")),
    false,
    "sibling session must not be treated as revoked",
  );
  const logoutFindings = ws.findings.filter((f) => /logout/i.test(f.title));
  assert.ok(logoutFindings.some((f) => f.confidence === "confirmed"));
  assert.equal(
    logoutFindings.every((f) => !/SID_B|TOK_DEVICE_B/.test(f.evidence.join(" "))),
    true,
  );
});

test("logout with no credential does not confirm leftover sessions", () => {
  const raw = har([
    entry("2026-08-30T01:00:00.000Z", "GET", "https://shop.lab/api/me", 200, [
      { name: "Authorization", value: "Bearer KEEP_ME" },
    ]),
    entry("2026-08-30T01:00:01.000Z", "POST", "https://shop.lab/api/logout", 200, []),
    entry("2026-08-30T01:00:02.000Z", "GET", "https://shop.lab/api/me", 200, [
      { name: "Authorization", value: "Bearer KEEP_ME" },
    ]),
  ]);
  const ws = analyze(raw, "", "alice", "bob");
  const f = ws.findings.filter((x) => /logout/i.test(x.title));
  assert.equal(f.some((x) => x.confidence === "confirmed"), false);
  assert.equal(tokensAliveAfterLogout(ws.requests, ws.policy).length, 0);
});

test("public path named logout is not a session-logout analysis target", () => {
  const page = req({
    method: "GET",
    path: "/docs/logout",
    template: "/docs/logout",
    requestHeaders: [],
    status: 200,
  });
  assert.equal(isLogoutAnalysisTarget(page), false);
  const raw = har([
    entry("2026-08-30T01:00:00.000Z", "GET", "https://shop.lab/api/me", 200, [
      { name: "Authorization", value: "Bearer KEEP_ME" },
    ]),
    entry("2026-08-30T01:00:01.000Z", "GET", "https://shop.lab/docs/logout", 200, []),
    entry("2026-08-30T01:00:02.000Z", "GET", "https://shop.lab/api/me", 200, [
      { name: "Authorization", value: "Bearer KEEP_ME" },
    ]),
  ]);
  const ws = analyze(raw, "", "alice", "bob");
  assert.equal(ws.findings.some((f) => /logout/i.test(f.title) && f.confidence === "confirmed"), false);
});

test("cookie+bearer logout only revokes those values, not a later rotated token", () => {
  const raw = har([
    entry("2026-08-30T01:00:00.000Z", "GET", "https://shop.lab/api/me", 200, [
      { name: "Authorization", value: "Bearer OLD_ACCESS" },
      { name: "Cookie", value: "sid=OLD_SID" },
    ]),
    entry("2026-08-30T01:00:01.000Z", "POST", "https://shop.lab/api/token/refresh", 200, [
      { name: "Authorization", value: "Bearer OLD_ACCESS" },
    ]),
    entry("2026-08-30T01:00:02.000Z", "POST", "https://shop.lab/api/logout", 204, [
      { name: "Authorization", value: "Bearer OLD_ACCESS" },
      { name: "Cookie", value: "sid=OLD_SID" },
    ]),
    entry("2026-08-30T01:00:03.000Z", "GET", "https://shop.lab/api/me", 200, [
      { name: "Authorization", value: "Bearer NEW_ACCESS" },
      { name: "Cookie", value: "sid=NEW_SID" },
    ]),
  ]);
  const ws = analyze(raw, "", "alice", "bob");
  const hits = tokensAliveAfterLogout(ws.requests, ws.policy);
  assert.equal(hits.length, 0);
});
