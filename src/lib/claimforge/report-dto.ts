import { cvssDraft, mapCweOwasp } from "./cwe.ts";
import { neutralizeFormula } from "./escape.ts";
import { redactText, redactWorkspace } from "./redact.ts";
import type { Finding, Workspace } from "./types.ts";
import { ENGINE_VERSION, RULE_VERSION } from "./versions.ts";

export const REPORT_SCHEMA_VERSION = "report-dto-1";

export interface ReportFindingDTO {
  id: string;
  severity: Finding["severity"];
  confidence: Finding["confidence"];
  reviewState: Finding["reviewState"];
  title: string;
  why: string;
  how: string;
  evidence: string[];
  endpoint?: string;
  cwe: string[];
  owasp: string[];
  cvssDraft: { score: number | null; vector: string | null; status: "draft" };
  preconditions: string[];
  reproduce: string[];
  expected: string;
  actual: string;
  impact: string;
  remediation: string;
  retest: string | null;
  reasonCodes: string[];
  missingEvidence: string[];
}

export interface ReportDTO {
  schemaVersion: typeof REPORT_SCHEMA_VERSION;
  tool: "ClaimForge";
  secrets: "redacted";
  generated: string;
  engineVersion: string;
  ruleVersion: string;
  policyVersion: string;
  inputHash: string;
  resultHash: string;
  actors: { A: string; B: string };
  findings: ReportFindingDTO[];
  diffs: {
    method: string;
    template: string;
    aStatuses: number[];
    bStatuses: number[];
    verdict: string;
    note: string;
  }[];
  timeline: { at: number; actor: string; kind: string; label: string; detail: string }[];
  jwts: { actor: string; alg?: string; parts: number; sigStatus: string; issues: string[] }[];
  cookies: {
    actor: string;
    name: string;
    flags: unknown;
    issues: string[];
    source: string;
  }[];
  graph: {
    nodes: { id: string; kind: string; label: string; bola: boolean }[];
    edges: { from: string; to: string; kind: string; bola: boolean }[];
  };
  loot: { kind: string; severity: string; label: string; value: string; where: string; actor: string }[];
  wordlists: { ids: string[]; emails: string[]; roles: string[]; hosts: string[] };
  paths: Workspace["paths"];
  replays: {
    id: string;
    title: string;
    severity: string;
    note: string;
    curl: string;
    raw: string;
    credentialSource?: { actor: string; kinds: string[] };
    strippedHeaders?: string[];
    headerDiff?: { name: string; before: string; after: string }[];
  }[];
  surface: {
    method: string;
    template: string;
    hosts: string[];
    statuses: number[];
    actors: string[];
    auth: boolean;
  }[];
  specCoverage?: {
    source: "openapi3" | "swagger2";
    title: string;
    version: string;
    declaredCount: number;
    coveredCount: number;
    untested: { method: string; path: string; secured: boolean; write: boolean; deprecated: boolean; summary: string }[];
    shadow: { method: string; template: string; statuses: number[] }[];
    error?: string;
  };
  truncation?: {
    totalA: number;
    totalB: number;
    droppedA: number;
    droppedB: number;
    perActorLimit: number;
  };
  redaction: {
    dropped: string[];
    preview: string[];
  };
}

const DROPPED = [
  "aRaw",
  "bRaw",
  "requests",
  "jwt.raw",
  "jwt.payload",
  "jwt.signature",
  "cookie.value",
  "diff.aSample",
  "diff.bSample",
  "canonical.capture raw",
];

function findingDto(f: Finding): ReportFindingDTO {
  const maps = mapCweOwasp(f.title, f.fingerprint);
  return {
    id: f.id,
    severity: f.severity,
    confidence: f.confidence,
    reviewState: f.reviewState,
    title: redactText(f.title),
    why: redactText(f.why),
    how: redactText(f.how),
    evidence: f.evidence.map((e) => redactText(e)),
    endpoint: f.template,
    cwe: maps.cwe,
    owasp: maps.owasp,
    cvssDraft: cvssDraft(f.severity),
    preconditions: ["Two captured actors", "Same route template"],
    reproduce: [redactText(f.how)],
    expected: "Object-level authorization denies cross-actor 2xx",
    actual: redactText(f.why),
    impact: f.severity === "critical" || f.severity === "high" ? "Cross-actor data exposure (heuristic)" : "Informational",
    remediation: redactText(f.how),
    retest: f.reviewState === "retest-passed" ? "passed" : f.reviewState === "retest-failed" ? "failed" : null,
    reasonCodes: f.reasonCodes,
    missingEvidence: (f.missingEvidence ?? []).map((e) => redactText(e)),
  };
}

export function toReportDTO(ws: Workspace, generated = new Date().toISOString()): ReportDTO {
  const safe = redactWorkspace(ws);
  const wl = {
    ids: safe.wordlists.ids.map((x) => neutralizeFormula(redactText(x))),
    emails: safe.wordlists.emails.map((x) => neutralizeFormula(redactText(x))),
    roles: safe.wordlists.roles.map((x) => neutralizeFormula(redactText(x))),
    hosts: safe.wordlists.hosts.map((x) => neutralizeFormula(redactText(x))),
  };
  return {
    schemaVersion: REPORT_SCHEMA_VERSION,
    tool: "ClaimForge",
    secrets: "redacted",
    generated,
    engineVersion: safe.engineVersion || ENGINE_VERSION,
    ruleVersion: safe.ruleVersion || RULE_VERSION,
    policyVersion: safe.policyVersion,
    inputHash: safe.inputHash,
    resultHash: safe.resultHash,
    actors: { A: safe.aLabel, B: safe.bLabel },
    findings: safe.findings.map(findingDto),
    diffs: safe.diffs.map((d) => ({
      method: d.method,
      template: d.template,
      aStatuses: d.aStatuses,
      bStatuses: d.bStatuses,
      verdict: d.verdict,
      note: redactText(d.note),
    })),
    timeline: safe.timeline.map((t) => ({
      at: t.at,
      actor: t.actor,
      kind: t.kind,
      label: redactText(t.label),
      detail: redactText(t.detail),
    })),
    jwts: safe.jwts.map((j) => ({
      actor: j.actor,
      alg: j.alg,
      parts: j.parts,
      sigStatus: j.sigStatus,
      issues: j.issues,
    })),
    cookies: safe.cookies.map((c) => ({
      actor: c.actor,
      name: c.name,
      flags: c.flags,
      issues: c.issues,
      source: c.source,
    })),
    graph: {
      nodes: safe.graph.nodes.map((n) => ({
        id: n.id,
        kind: n.kind,
        label: redactText(n.label),
        bola: n.bola,
      })),
      edges: safe.graph.edges.map((e) => ({ from: e.from, to: e.to, kind: e.kind, bola: e.bola })),
    },
    loot: safe.loot.map((l) => ({
      kind: l.kind,
      severity: l.severity,
      label: redactText(l.label),
      value: redactText(l.value),
      where: redactText(l.where),
      actor: l.actor,
    })),
    wordlists: wl,
    paths: safe.paths.map((p) => ({
      ...p,
      title: redactText(p.title),
      objective: redactText(p.objective),
      steps: p.steps.map((s) => redactText(s)),
    })),
    replays: safe.replays.map((r) => ({
      id: r.id,
      title: redactText(r.title),
      severity: r.severity,
      note: redactText(r.note),
      curl: redactText(r.curl),
      raw: redactText(r.raw),
      credentialSource: r.credentialSource,
      strippedHeaders: r.strippedHeaders,
      headerDiff: r.headerDiff?.map((d) => ({
        name: d.name,
        before: redactText(d.before),
        after: redactText(d.after),
      })),
    })),
    surface: safe.surface.map((s) => ({
      method: s.method,
      template: s.template,
      hosts: s.hosts,
      statuses: s.statuses,
      actors: s.actors,
      auth: s.auth,
    })),
    specCoverage: safe.specCoverage
      ? {
          source: safe.specCoverage.source,
          title: redactText(safe.specCoverage.title),
          version: safe.specCoverage.version,
          declaredCount: safe.specCoverage.declaredCount,
          coveredCount: safe.specCoverage.coveredCount,
          untested: safe.specCoverage.untested.map((o) => ({
            method: o.method,
            path: redactText(o.path),
            secured: o.secured,
            write: o.write,
            deprecated: o.deprecated,
            summary: redactText(o.summary),
          })),
          shadow: safe.specCoverage.shadow.map((s) => ({
            method: s.method,
            template: redactText(s.template),
            statuses: s.statuses,
          })),
          error: safe.specCoverage.error ? redactText(safe.specCoverage.error) : undefined,
        }
      : undefined,
    truncation: safe.truncation
      ? {
          totalA: safe.truncation.totalA,
          totalB: safe.truncation.totalB,
          droppedA: safe.truncation.droppedA,
          droppedB: safe.truncation.droppedB,
          perActorLimit: safe.truncation.perActorLimit,
        }
      : undefined,
    redaction: {
      dropped: DROPPED,
      preview: [
        "Raw HAR/JWT compact tokens dropped",
        "Cookie values dropped",
        "Diff request/response samples dropped",
        "JWT payload/signature dropped",
        "Secret-named JSON keys masked",
      ],
    },
  };
}
