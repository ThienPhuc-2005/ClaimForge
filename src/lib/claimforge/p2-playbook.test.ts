import assert from "node:assert/strict";
import { test } from "node:test";
import { buildPaths, buildReplays, csrfPoc } from "./playbook.ts";
import { analyze } from "./analyze.ts";
import type { CapturedRequest, Finding, Workspace } from "./types.ts";

function req(p: Partial<CapturedRequest>): CapturedRequest {
  return {
    id: "r",
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
    ...p,
  };
}

function finding(p: Partial<Finding>): Finding {
  return {
    id: "F1",
    severity: "medium",
    confidence: "suspicion",
    title: "t",
    why: "w",
    evidence: [],
    how: "h",
    reasonCodes: ["CAPTURE_HEURISTIC_ONLY"],
    reviewState: "needs-evidence",
    ...p,
  };
}

const emptyGraph = { nodes: [], edges: [] };

function replayWs(requests: CapturedRequest[], findings: Finding[]): Pick<
  Workspace,
  "requests" | "jwts" | "graph" | "aLabel" | "bLabel" | "findings"
> {
  return { requests, jwts: [], graph: emptyGraph, aLabel: "A", bLabel: "B", findings };
}

function pathsWs(findings: Finding[]) {
  return { findings, jwts: [], graph: emptyGraph, loot: [], aLabel: "A", bLabel: "B", diffs: [] };
}

test("BFLA finding yields an attack path and a replay curl with the actor's credentials", () => {
  const sample = req({
    actor: "B",
    method: "GET",
    url: "https://shop.lab/admin/users",
    path: "/admin/users",
    template: "/admin/users",
    status: 200,
    requestHeaders: [{ name: "Cookie", value: "session=abcdef0123456789ab" }],
  });
  const f = finding({ id: "F1", fingerprint: "bfla:B:GET:/admin/users", template: "/admin/users" });
  const replays = buildReplays(replayWs([sample], [f]));
  const bfla = replays.find((r) => r.id.startsWith("replay-bfla"));
  assert.ok(bfla, "expected a BFLA replay");
  assert.match(bfla!.title, /BFLA/);
  assert.match(bfla!.curl, /\/admin\/users/);

  const paths = buildPaths(pathsWs([f]));
  assert.ok(paths.some((p) => p.id === "path-bfla" && p.findingIds.includes("F1")));
});

test("CSRF finding yields a cross-site PoC replay and an attack path", () => {
  const sample = req({
    method: "POST",
    path: "/account/email",
    template: "/account/email",
    requestHeaders: [{ name: "Cookie", value: "session=abcdef0123456789ab" }],
    requestBody: "email=attacker@evil.test",
  });
  const f = finding({ id: "F2", fingerprint: "csrf:POST:/account/email", template: "/account/email" });
  const replays = buildReplays(replayWs([sample], [f]));
  const csrf = replays.find((r) => r.id.startsWith("replay-csrf"));
  assert.ok(csrf, "expected a CSRF replay");
  assert.match(csrf!.curl, /credentials: "include"/);
  assert.match(csrf!.raw, /<form/); // form-encoded body → auto-submit HTML form

  const paths = buildPaths(pathsWs([f]));
  assert.ok(paths.some((p) => p.id === "path-csrf" && p.findingIds.includes("F2")));
});

test("csrfPoc emits a fetch snippet for JSON bodies and a form for urlencoded", () => {
  const json = csrfPoc(req({ method: "POST", requestBody: '{"email":"x@y.z"}', requestHeaders: [{ name: "content-type", value: "application/json" }] }));
  assert.equal(json.isForm, false);
  assert.match(json.fetch, /credentials: "include"/);

  const form = csrfPoc(req({ method: "POST", requestBody: "a=1&b=2" }));
  assert.equal(form.isForm, true);
  assert.match(form.html, /name="a"/);
});

test("refresh finding yields a refresh replay and an attack path", () => {
  const sample = req({
    actor: "A",
    method: "POST",
    url: "https://shop.lab/oauth/token",
    path: "/oauth/token",
    template: "/oauth/token",
    status: 200,
    requestBody: "grant_type=refresh_token&refresh_token=RTOLDAAAAAAAA",
  });
  const f = finding({ id: "F3", fingerprint: "refresh:A:reuse:RTOL", template: "/oauth/token" });
  const replays = buildReplays(replayWs([sample], [f]));
  const refresh = replays.find((r) => r.id.startsWith("replay-refresh"));
  assert.ok(refresh, "expected a refresh replay");
  assert.match(refresh!.curl, /oauth\/token/);

  const paths = buildPaths(pathsWs([f]));
  assert.ok(paths.some((p) => p.id === "path-refresh" && p.findingIds.includes("F3")));
});

test("end-to-end: analyze() surfaces a BFLA path + replay from a capture", () => {
  const har = (entries: object[]) => JSON.stringify({ log: { entries } });
  const entry = (actor: string, status: number) => ({
    startedDateTime: "2026-01-01T00:00:00Z",
    request: {
      method: "DELETE",
      url: "https://shop.lab/admin/users/9",
      headers: [{ name: "Cookie", value: `session=${actor}bcdef0123456789ab` }],
    },
    response: { status, headers: [], content: { text: "{}" } },
  });
  // Actor A (admin) denied 403 → enforcement; actor B 2xx → bypass on an enforced admin function.
  const ws = analyze(har([entry("a", 403)]), har([entry("b", 200)]), "admin", "user");
  assert.ok(ws.findings.some((f) => (f.fingerprint ?? "").startsWith("bfla:")), "expected a BFLA finding");
  assert.ok(ws.paths.some((p) => p.id === "path-bfla"), "expected a BFLA attack path");
  assert.ok(ws.replays.some((r) => r.id.startsWith("replay-bfla")), "expected a BFLA replay");
});
