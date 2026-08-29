import assert from "node:assert/strict";
import { test } from "node:test";
import { analyze } from "./analyze.ts";
import { classifyTimeline, tokensAliveAfterLogout } from "./session.ts";
import type { CapturedRequest } from "./types.ts";
import { demoActorA, demoActorB } from "./demo.ts";

function req(partial: Partial<CapturedRequest>): CapturedRequest {
  return {
    id: "t",
    actor: "A",
    startedAt: 1,
    method: "GET",
    url: "https://shop.lab/x",
    origin: "https://shop.lab",
    path: "/x",
    template: "/x",
    query: {},
    requestHeaders: [],
    status: 200,
    statusText: "OK",
    responseHeaders: [],
    timeMs: 0,
    ...partial,
  };
}

test("timeline classifies login refresh logout", () => {
  assert.equal(classifyTimeline(req({ method: "POST", path: "/api/login", template: "/api/login" })).kind, "login");
  assert.equal(classifyTimeline(req({ method: "POST", path: "/api/token/refresh", template: "/api/token/refresh" })).kind, "refresh");
  assert.equal(classifyTimeline(req({ method: "POST", path: "/api/logout", template: "/api/logout" })).kind, "logout");
  assert.equal(classifyTimeline(req({ method: "GET", path: "/api/me", template: "/api/me", requestHeaders: [{ name: "Authorization", value: "Bearer a.b.c" }] })).kind, "authz");
});

function capture(host: string, logoutStatus = 200) {
  const tok = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.sig";
  return JSON.stringify({
    log: {
      entries: [
        {
          startedDateTime: "2026-08-29T05:00:00.000Z",
          request: {
            method: "POST",
            url: `https://${host}/api/login`,
            headers: [],
            postData: { text: "{\"email\":\"a\"}" },
          },
          response: { status: 200, headers: [], content: { text: JSON.stringify({ token: tok }) } },
        },
        {
          startedDateTime: "2026-08-29T05:00:01.000Z",
          request: {
            method: "GET",
            url: `https://${host}/api/me`,
            headers: [{ name: "Authorization", value: `Bearer ${tok}` }],
          },
          response: { status: 200, headers: [], content: { text: "{\"id\":\"alice\"}" } },
        },
        {
          startedDateTime: "2026-08-29T05:00:02.000Z",
          request: {
            method: "POST",
            url: `https://${host}/api/logout`,
            headers: [{ name: "Authorization", value: `Bearer ${tok}` }],
          },
          response: { status: logoutStatus, headers: [], content: { text: "{\"ok\":true}" } },
        },
        {
          startedDateTime: "2026-08-29T05:00:03.000Z",
          request: {
            method: "GET",
            url: `https://${host}/api/me`,
            headers: [{ name: "Authorization", value: `Bearer ${tok}` }],
          },
          response: { status: 200, headers: [], content: { text: "{\"id\":\"alice\"}" } },
        },
      ],
    },
  });
}

test("lab token 2xx after 2xx logout is confirmed", () => {
  const ws = analyze(capture("shop.lab"), "", "alice", "bob");
  assert.ok(ws.timeline.some((t) => t.kind === "logout"));
  assert.ok(tokensAliveAfterLogout(ws.requests).length >= 1);
  assert.ok(ws.findings.some((f) => /logout/i.test(f.title) && f.confidence === "confirmed"));
});

test("outside lab post-logout 2xx is suspicion only", () => {
  const ws = analyze(capture("api.example.com"), "", "alice", "bob");
  const f = ws.findings.find((x) => /logout/i.test(x.title));
  assert.ok(f);
  assert.equal(f?.confidence, "suspicion");
});

test("logout that did not 2xx is not confirmed", () => {
  const ws = analyze(capture("shop.lab", 500), "", "alice", "bob");
  const f = ws.findings.find((x) => /logout/i.test(x.title));
  assert.ok(!f || f.confidence !== "confirmed");
});

test("demo capture flags bob token after logout", () => {
  const ws = analyze(demoActorA(), demoActorB(), "alice", "bob");
  assert.ok(ws.timeline.some((t) => t.kind === "login"));
  assert.ok(ws.timeline.some((t) => t.kind === "refresh"));
  assert.ok(ws.timeline.some((t) => t.kind === "logout"));
  assert.ok(ws.findings.some((f) => /logout/i.test(f.title) && f.confidence === "confirmed"));
});
