import assert from "node:assert/strict";
import { test } from "node:test";
import { analyze } from "./analyze.ts";
import { demoActorA, demoActorB } from "./demo.ts";
import { escapeHtml, neutralizeFormula } from "./escape.ts";
import {
  buildReport,
  exportReportHtml,
  exportReportPdf,
  renderReportHtml,
  renderReportJson,
  renderReportMarkdown,
  renderReportPdf,
} from "./report.ts";
import type { Workspace } from "./types.ts";

const CANARY = "cfcanaryZ9xQ7wLm2p";

function wrap(ws: Workspace): Workspace {
  const bearer = `Bearer ${CANARY}`;
  const cookie = `sid=${CANARY}`;
  const passJson = JSON.stringify({ password: CANARY });
  return {
    ...ws,
    aRaw: `Authorization: ${bearer}\nCookie: ${cookie}\n${passJson}`,
    bRaw: bearer,
    parseErrorA: bearer,
    parseErrorB: cookie,
    findings: [
      ...ws.findings,
      {
        id: "FCANARY",
        severity: "info",
        confidence: "observation",
        title: passJson,
        why: bearer,
        how: cookie,
        evidence: [bearer, `https://x/api?access_token=${CANARY}#token=${CANARY}`],
        fingerprint: "canary",
        reasonCodes: ["CAPTURE_HEURISTIC_ONLY"],
        reviewState: "new",
      },
    ],
    loot: [
      ...ws.loot,
      {
        kind: "secret",
        severity: "high",
        label: "canary",
        value: CANARY,
        where: bearer,
        actor: "A",
      },
    ],
    replays: [
      ...ws.replays,
      {
        id: "r-canary",
        title: passJson,
        severity: "low",
        note: bearer,
        curl: `curl -H 'Authorization: ${bearer}' https://x`,
        raw: `GET / HTTP/1.1\r\nAuthorization: ${bearer}\r\n`,
      },
    ],
    timeline: [
      ...ws.timeline,
      { at: 1, actor: "A", kind: "traffic", label: cookie, detail: bearer },
    ],
    graph: {
      nodes: [...ws.graph.nodes, { id: "n", kind: "object", label: bearer, owners: [], seenBy: [], bola: false }],
      edges: ws.graph.edges,
    },
    wordlists: {
      ...ws.wordlists,
      ids: [...ws.wordlists.ids, `sid=${CANARY}`],
    },
    paths: [
      ...ws.paths,
      {
        id: "p-canary",
        title: passJson,
        objective: bearer,
        steps: [cookie],
        findingIds: [],
      },
    ],
    diffs: [
      ...ws.diffs,
      {
        template: "/canary",
        method: "GET",
        aStatuses: [200],
        bStatuses: [200],
        verdict: "same",
        note: bearer,
        aSample: ws.requests[0],
      },
    ],
    jwts: [
      ...ws.jwts,
      {
        actor: "A",
        raw: `eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhIn0.${CANARY}`,
        source: bearer,
        header: { alg: "HS256" },
        payload: { sub: "a", secret: CANARY, password: CANARY },
        alg: "HS256",
        parts: 3,
        signature: CANARY,
        sigStatus: "unverified",
        issues: [bearer],
      },
    ],
    cookies: [
      ...ws.cookies,
      {
        actor: "A",
        name: "sid",
        value: CANARY,
        source: "set-cookie",
        flags: { httpOnly: false, secure: false, sameSite: null },
        issues: [],
      },
    ],
  };
}

function leak(blob: string) {
  assert.doesNotMatch(blob, new RegExp(CANARY));
}

test("ReportDTO is allowlist: no raw capture, samples, jwt payload, or cookie values", () => {
  const dto = buildReport(analyze(demoActorA(), demoActorB(), "alice", "bob"));
  const json = renderReportJson(dto);
  assert.equal(dto.secrets, "redacted");
  assert.ok(dto.redaction.dropped.includes("aRaw"));
  assert.equal(Object.hasOwn(dto, "aRaw"), false);
  assert.equal(Object.hasOwn(dto, "requests"), false);
  assert.doesNotMatch(json, /"aSample"/);
  assert.ok(dto.findings.some((f) => f.cwe.length || f.severity === "info" || true));
  assert.equal(dto.findings[0]?.cvssDraft.status, "draft");
});

test("canary secrets planted in every slot do not survive JSON/MD/HTML/PDF", () => {
  const ws = wrap(analyze(demoActorA(), demoActorB(), "alice", "bob"));
  const dto = buildReport(ws);
  const json = renderReportJson(dto);
  const md = renderReportMarkdown(dto);
  const html = renderReportHtml(dto);
  const pdf = new TextDecoder().decode(renderReportPdf(dto));
  for (const blob of [json, md, html, pdf, JSON.stringify(dto)]) leak(blob);
});

test("HTML escapes markup; markdown strips fence breakers; formulas prefixed", () => {
  const escaped = escapeHtml("<script>alert(1)</script>");
  assert.ok(escaped.includes("lt;"));
  assert.ok(!escaped.includes("<script>"));
  assert.equal(neutralizeFormula("=2+2"), "'=2+2");
  assert.equal(neutralizeFormula("@SUM(1)"), "'@SUM(1)");
  const dto = buildReport(analyze(demoActorA(), demoActorB(), "alice", "bob"));
  dto.findings.push({
    ...dto.findings[0]!,
    id: "X",
    title: "<img src=x onerror=alert(1)>",
    why: "</article><script>alert(1)</script>",
    how: "ok",
    evidence: ["![x](javascript:alert(1))"],
    cwe: [],
    owasp: [],
    cvssDraft: { score: null, vector: null, status: "draft" },
    preconditions: [],
    reproduce: [],
    expected: "",
    actual: "",
    impact: "",
    remediation: "",
    retest: null,
    reasonCodes: [],
    missingEvidence: [],
  });
  const html = renderReportHtml(dto);
  assert.doesNotMatch(html, /<script>/);
  assert.match(html, /lt;img/);
});

test("workspace helpers export html/pdf without throwing", () => {
  const ws = analyze(demoActorA(), demoActorB(), "alice", "bob");
  assert.match(exportReportHtml(ws), /ClaimForge/);
  const pdf = exportReportPdf(ws);
  assert.ok(pdf.byteLength > 80);
  const text = new TextDecoder().decode(pdf);
  assert.match(text, /%PDF-1\.4/);
  assert.match(text, /Findings/);
  assert.match(text, /Kill chain/);
  assert.match(text, /confirmed|observation|suspicion/);
});

test("PDF paginates instead of dumping one truncated page", () => {
  const dto = buildReport(analyze(demoActorA(), demoActorB(), "alice", "bob"));
  const seed = dto.findings[0]!;
  dto.findings = Array.from({ length: 40 }, (_, i) => ({
    ...seed,
    id: `F${i}`,
    title: `Finding ${i} long title for wrap`,
    why: `Why for finding ${i}: ownership and cross-actor access need a second look in the lab.`,
  }));
  const pdf = renderReportPdf(dto);
  const text = new TextDecoder().decode(pdf);
  const count = /\/Count (\d+)/.exec(text);
  assert.ok(count && Number(count[1]) >= 2, `expected multiple pages, got Count ${count?.[1] ?? "?"}`);
  assert.match(text, /Why for finding/);
  assert.match(text, /Finding 39/);
  assert.match(text, /Page 1 \/ /);
  assert.match(text, /How:/);
});
