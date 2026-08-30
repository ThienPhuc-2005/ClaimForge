import { z } from "zod";
import {
  clonePolicy,
  sanitizePolicy,
  validatePolicyPatterns,
  type AnalysisPolicy,
} from "../claimforge/policy.ts";
import { redactText } from "../claimforge/redact.ts";
import { REPORT_SCHEMA_VERSION } from "../claimforge/report-dto.ts";
import { REVIEW_STATES } from "../claimforge/review.ts";
import type { ReviewState } from "../claimforge/types.ts";
import { TeamPersistError } from "./errors.ts";
import type { CollabWrite } from "./types.ts";

export const TEAM_LIMITS = {
  policyBytes: 64 * 1024,
  reviewBytes: 64 * 1024,
  reportBytes: 512 * 1024,
  stringChars: 8 * 1024,
  shortChars: 256,
  fingerprintChars: 256,
  reviewEntries: 2_000,
  listItems: 100,
  reportItems: 500,
  wordlistItems: 2_000,
  graphEdges: 1_000,
  base64Run: 4_096,
} as const;

const REDACTED = "[redacted]" as const;

const COMPACT_JWT = /eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*/;
const PEM_PRIVATE = /BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY/;
const BEARER = /\bBearer\s+(?!\[redacted\])\S+/i;
const BASIC = /\bBasic\s+(?!\[redacted\])\S+/i;
const COOKIE_LINE = /(?:^|[\r\n])(?:Cookie|Set-Cookie):\s*(?!\[redacted\]\s*$)/im;
const CURL_USER = /(?:^|\s)(?:-u|--user)\s+(?!\[redacted\])\S+/;
const AWS_ACCESS_KEY = /\bAKIA[0-9A-Z]{16}\b/;
const HTTP_REQUEST = /^(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|CONNECT|TRACE)\s+\S+\s+HTTP\/\d/im;
const BASE64_RUN = /[A-Za-z0-9+/]{4096,}={0,2}/;
const API_KEY_ASSIGN = /\bapi[_-]?key\s*[:=]\s*(?!\[redacted\])\S+/i;
const SESSION_SECRET_ASSIGN = /\bsession[_-]?secret\s*[:=]\s*(?!\[redacted\])\S+/i;

const FORBIDDEN_KEYS = new Set([
  "araw",
  "braw",
  "requests",
  "authorization",
  "cookie",
  "setcookie",
  "set-cookie",
  "accesstoken",
  "refreshtoken",
  "idtoken",
  "clientsecret",
  "password",
  "privatekey",
  "apikey",
  "xapikey",
  "sessionsecret",
  "session",
  "secret",
  "token",
  "jwt",
  "har",
]);

const POLICY_KEYS = new Set([
  "version",
  "publicPathPatterns",
  "sharedPathPatterns",
  "privatePathPatterns",
  "identityPathPatterns",
  "inventoryFields",
  "trustedOwnershipFields",
  "successStatuses",
  "denyStatuses",
  "requireJwtIss",
  "requireJwtAud",
  "roleHierarchy",
  "logoutPathPatterns",
  "jwksHostnameAllowlist",
  "jwksTeamMode",
]);

const COLLAB_KEYS = new Set(["policy", "review", "reportDto"]);

const SEVERITY = z.enum(["critical", "high", "medium", "low", "info"]);
const CONFIDENCE = z.enum(["observation", "suspicion", "confirmed"]);
const REVIEW_STATE = z.enum(REVIEW_STATES as unknown as [ReviewState, ...ReviewState[]]);
const ACTOR = z.enum(["A", "B"]);

const str = (max = TEAM_LIMITS.stringChars) => z.string().max(max);
const short = str(TEAM_LIMITS.shortChars);
const strList = (maxItems: number, maxChars = TEAM_LIMITS.stringChars) =>
  z.array(str(maxChars)).max(maxItems);
const numList = (maxItems: number) => z.array(z.number().finite()).max(maxItems);

const CookieFlagsSchema = z.strictObject({
  httpOnly: z.boolean(),
  secure: z.boolean(),
  sameSite: z.string().nullable(),
  path: short.optional(),
  domain: short.optional(),
  maxAge: short.optional(),
  expires: short.optional(),
});

const FindingSchema = z.strictObject({
  id: short,
  severity: SEVERITY,
  confidence: CONFIDENCE,
  reviewState: REVIEW_STATE,
  title: str(),
  why: str(),
  how: str(),
  evidence: strList(TEAM_LIMITS.reportItems),
  endpoint: str().optional(),
  cwe: strList(32, 64),
  owasp: strList(32, 128),
  cvssDraft: z.strictObject({
    score: z.number().finite().nullable(),
    vector: str(256).nullable(),
    status: z.literal("draft"),
  }),
  preconditions: strList(32),
  reproduce: strList(32),
  expected: str(),
  actual: str(),
  impact: str(),
  remediation: str(),
  retest: str(64).nullable(),
  reasonCodes: strList(64, 64),
  missingEvidence: strList(64),
});

const lootSchema = (value: z.ZodType) =>
  z.strictObject({
    kind: short,
    severity: short,
    label: str(),
    value,
    where: str(),
    actor: ACTOR,
  });

const replaySchema = (blob: z.ZodType) =>
  z.strictObject({
    id: short,
    title: str(),
    severity: short,
    note: str(),
    curl: blob,
    raw: blob,
    credentialSource: z
      .strictObject({
        actor: short,
        kinds: strList(16, 64),
      })
      .optional(),
    strippedHeaders: strList(64, TEAM_LIMITS.shortChars).optional(),
    headerDiff: z
      .array(
        z.strictObject({
          name: short,
          before: str(),
          after: str(),
        }),
      )
      .max(64)
      .optional(),
  });

function reportDtoShape(lootValue: z.ZodType, replayBlob: z.ZodType) {
  return z.strictObject({
    schemaVersion: z.literal(REPORT_SCHEMA_VERSION),
    tool: z.literal("ClaimForge"),
    secrets: z.literal("redacted"),
    generated: short,
    engineVersion: short,
    ruleVersion: short,
    policyVersion: short,
    inputHash: short,
    resultHash: short,
    actors: z.strictObject({ A: short, B: short }),
    findings: z.array(FindingSchema).max(TEAM_LIMITS.reportItems),
    diffs: z
      .array(
        z.strictObject({
          method: short,
          template: str(),
          aStatuses: numList(32),
          bStatuses: numList(32),
          verdict: short,
          note: str(),
        }),
      )
      .max(TEAM_LIMITS.reportItems),
    timeline: z
      .array(
        z.strictObject({
          at: z.number().finite(),
          actor: short,
          kind: short,
          label: str(),
          detail: str(),
        }),
      )
      .max(TEAM_LIMITS.wordlistItems),
    jwts: z
      .array(
        z.strictObject({
          actor: short,
          alg: short.optional(),
          parts: z.number().int().nonnegative(),
          sigStatus: short,
          issues: strList(32),
        }),
      )
      .max(TEAM_LIMITS.reportItems),
    cookies: z
      .array(
        z.strictObject({
          actor: short,
          name: short,
          flags: CookieFlagsSchema,
          issues: strList(32),
          source: short,
        }),
      )
      .max(TEAM_LIMITS.reportItems),
    graph: z.strictObject({
      nodes: z
        .array(
          z.strictObject({
            id: short,
            kind: short,
            label: str(),
            bola: z.boolean(),
          }),
        )
        .max(TEAM_LIMITS.reportItems),
      edges: z
        .array(
          z.strictObject({
            from: short,
            to: short,
            kind: short,
            bola: z.boolean(),
          }),
        )
        .max(TEAM_LIMITS.graphEdges),
    }),
    loot: z.array(lootSchema(lootValue)).max(TEAM_LIMITS.reportItems),
    wordlists: z.strictObject({
      ids: strList(TEAM_LIMITS.wordlistItems, TEAM_LIMITS.shortChars),
      emails: strList(TEAM_LIMITS.wordlistItems, TEAM_LIMITS.shortChars),
      roles: strList(TEAM_LIMITS.wordlistItems, TEAM_LIMITS.shortChars),
      hosts: strList(TEAM_LIMITS.wordlistItems, TEAM_LIMITS.shortChars),
    }),
    paths: z
      .array(
        z.strictObject({
          id: short,
          title: str(),
          objective: str(),
          steps: strList(64),
          findingIds: strList(64, TEAM_LIMITS.shortChars),
        }),
      )
      .max(TEAM_LIMITS.listItems),
    replays: z.array(replaySchema(replayBlob)).max(TEAM_LIMITS.reportItems),
    surface: z
      .array(
        z.strictObject({
          method: short,
          template: str(),
          hosts: strList(32, TEAM_LIMITS.shortChars),
          statuses: numList(32),
          actors: strList(8, 8),
          auth: z.boolean(),
        }),
      )
      .max(TEAM_LIMITS.reportItems),
    redaction: z.strictObject({
      dropped: strList(64, TEAM_LIMITS.shortChars),
      preview: strList(64),
    }),
  });
}

const ReportDtoSchema = reportDtoShape(str(), str());
const TeamReportDtoSchema = reportDtoShape(z.literal(REDACTED), z.literal(REDACTED));

type ReportDtoInput = z.infer<typeof ReportDtoSchema>;

function utf8Bytes(value: string): number {
  return Buffer.byteLength(value, "utf8");
}

function fail(message: string): never {
  throw new TeamPersistError(message);
}

function normKey(key: string): string {
  return key.toLowerCase().replace(/[_-]/g, "");
}

function assertAllowedKey(key: string): void {
  const nk = normKey(key);
  if (nk === "tenantid") fail("tenant_id is not accepted from caller input");
  if (FORBIDDEN_KEYS.has(nk) || FORBIDDEN_KEYS.has(key.toLowerCase())) {
    fail(`forbidden persist key ${key}`);
  }
}

function assertUtf8Limit(json: string, limit: number, label: string): void {
  if (utf8Bytes(json) > limit) fail(`${label} exceeds ${limit} UTF-8 bytes`);
}

function mapStrings(value: unknown): unknown {
  if (typeof value === "string") return redactText(value);
  if (Array.isArray(value)) return value.map(mapStrings);
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
      out[key] = mapStrings(child);
    }
    return out;
  }
  return value;
}

function scanValue(value: unknown, path: string): void {
  if (value == null) return;
  if (typeof value === "string") {
    if (COMPACT_JWT.test(value)) fail(`forbidden compact JWT at ${path}`);
    if (PEM_PRIVATE.test(value)) fail(`forbidden private key at ${path}`);
    if (BEARER.test(value)) fail(`forbidden bearer token at ${path}`);
    if (BASIC.test(value)) fail(`forbidden basic credential at ${path}`);
    if (COOKIE_LINE.test(value)) fail(`forbidden cookie header at ${path}`);
    if (CURL_USER.test(value)) fail(`forbidden curl user at ${path}`);
    if (AWS_ACCESS_KEY.test(value)) fail(`forbidden aws access key at ${path}`);
    if (API_KEY_ASSIGN.test(value)) fail(`forbidden api_key at ${path}`);
    if (SESSION_SECRET_ASSIGN.test(value)) fail(`forbidden sessionSecret at ${path}`);
    if (BASE64_RUN.test(value)) fail(`oversize Base64 at ${path}`);
    if (HTTP_REQUEST.test(value)) fail(`forbidden raw HTTP at ${path}`);
    return;
  }
  if (typeof value === "number" || typeof value === "boolean") return;
  if (Array.isArray(value)) {
    value.forEach((item, i) => scanValue(item, `${path}[${i}]`));
    return;
  }
  if (typeof value !== "object") return;
  const rec = value as Record<string, unknown>;
  if ("log" in rec && rec.log && typeof rec.log === "object" && "entries" in (rec.log as object)) {
    fail(`forbidden HAR log at ${path}`);
  }
  for (const [key, child] of Object.entries(rec)) {
    assertAllowedKey(key);
    if (normKey(key) === "raw" && /jwt/i.test(path)) fail(`forbidden jwt.raw at ${path}.${key}`);
    if (normKey(key) === "value" && /cookie/i.test(path) && !/\.cookies\[\d+\]$/.test(path)) {
      fail(`forbidden cookie value at ${path}.${key}`);
    }
    scanValue(child, `${path}.${key}`);
  }
}

function parseOrThrow<T>(schema: z.ZodType<T>, value: unknown, label: string): T {
  const result = schema.safeParse(value);
  if (!result.success) fail(`${label} failed schema`);
  return result.data;
}

function projectTeamReportDto(dto: ReportDtoInput) {
  return {
    schemaVersion: dto.schemaVersion,
    tool: dto.tool,
    secrets: dto.secrets,
    generated: dto.generated,
    engineVersion: dto.engineVersion,
    ruleVersion: dto.ruleVersion,
    policyVersion: dto.policyVersion,
    inputHash: dto.inputHash,
    resultHash: dto.resultHash,
    actors: { A: dto.actors.A, B: dto.actors.B },
    findings: dto.findings.map((f) => ({ ...f })),
    diffs: dto.diffs.map((d) => ({ ...d })),
    timeline: dto.timeline.map((t) => ({ ...t })),
    jwts: dto.jwts.map((j) => ({ ...j })),
    cookies: dto.cookies.map((c) => ({ ...c, flags: { ...c.flags } })),
    graph: {
      nodes: dto.graph.nodes.map((n) => ({ ...n })),
      edges: dto.graph.edges.map((e) => ({ ...e })),
    },
    loot: dto.loot.map((item) => ({
      kind: item.kind,
      severity: item.severity,
      label: item.label,
      value: REDACTED,
      where: item.where,
      actor: item.actor,
    })),
    wordlists: {
      ids: [...dto.wordlists.ids],
      emails: [...dto.wordlists.emails],
      roles: [...dto.wordlists.roles],
      hosts: [...dto.wordlists.hosts],
    },
    paths: dto.paths.map((p) => ({ ...p, steps: [...p.steps], findingIds: [...p.findingIds] })),
    replays: dto.replays.map((item) => ({
      id: item.id,
      title: item.title,
      severity: item.severity,
      note: item.note,
      curl: REDACTED,
      raw: REDACTED,
      credentialSource: item.credentialSource ? { ...item.credentialSource, kinds: [...item.credentialSource.kinds] } : undefined,
      strippedHeaders: item.strippedHeaders ? [...item.strippedHeaders] : undefined,
      headerDiff: item.headerDiff?.map((d) => ({ ...d })),
    })),
    surface: dto.surface.map((s) => ({
      ...s,
      hosts: [...s.hosts],
      statuses: [...s.statuses],
      actors: [...s.actors],
    })),
    redaction: { dropped: [...dto.redaction.dropped], preview: [...dto.redaction.preview] },
  };
}

function finalizeTeamReportDto(value: unknown): unknown {
  const typed = parseOrThrow(TeamReportDtoSchema, value, "reportDto");
  scanValue(typed, "reportDto");
  const redacted = mapStrings(typed);
  const again = parseOrThrow(TeamReportDtoSchema, redacted, "reportDto");
  scanValue(again, "reportDto");
  const json = JSON.stringify(again);
  assertUtf8Limit(json, TEAM_LIMITS.reportBytes, "reportDto");
  return JSON.parse(json) as unknown;
}

export function assertPolicyPayload(policy: unknown): AnalysisPolicy {
  if (!policy || typeof policy !== "object" || Array.isArray(policy)) {
    fail("policy must be an object");
  }
  for (const key of Object.keys(policy as object)) {
    assertAllowedKey(key);
    if (!POLICY_KEYS.has(key)) fail(`unknown policy field ${key}`);
  }
  let next: AnalysisPolicy;
  try {
    next = sanitizePolicy(clonePolicy(policy as AnalysisPolicy));
  } catch {
    fail("policy is not a valid AnalysisPolicy");
  }
  const errors = validatePolicyPatterns(next);
  if (errors.length) fail(`policy regex invalid: ${errors[0]!.error}`);
  for (const list of [
    next.publicPathPatterns,
    next.sharedPathPatterns,
    next.privatePathPatterns,
    next.identityPathPatterns,
    next.inventoryFields,
    next.trustedOwnershipFields,
    next.requireJwtIss,
    next.requireJwtAud,
    next.logoutPathPatterns,
    next.jwksHostnameAllowlist,
  ]) {
    if (list.length > TEAM_LIMITS.listItems) fail("policy list too long");
    for (const item of list) {
      if (item.length > TEAM_LIMITS.stringChars) fail("policy string too long");
    }
  }
  if (next.successStatuses.length > TEAM_LIMITS.listItems || next.denyStatuses.length > TEAM_LIMITS.listItems) {
    fail("policy list too long");
  }
  for (const n of [...next.successStatuses, ...next.denyStatuses]) {
    if (!Number.isInteger(n) || n < 100 || n > 599) fail("policy status is invalid");
  }
  scanValue(next, "policy");
  const json = JSON.stringify(next);
  assertUtf8Limit(json, TEAM_LIMITS.policyBytes, "policy");
  return JSON.parse(json) as AnalysisPolicy;
}

export function assertReviewPayload(review: unknown): Record<string, ReviewState> {
  if (!review || typeof review !== "object" || Array.isArray(review)) {
    fail("review must be an object");
  }
  const entries = Object.entries(review as Record<string, unknown>);
  if (entries.length > TEAM_LIMITS.reviewEntries) fail("review has too many fingerprints");
  const out: Record<string, ReviewState> = {};
  for (const [fp, state] of entries) {
    assertAllowedKey(fp);
    if (!fp || fp.length > TEAM_LIMITS.fingerprintChars || fp.includes("\0")) {
      fail("review fingerprint is invalid");
    }
    if (!(REVIEW_STATES as readonly string[]).includes(state as string)) {
      fail(`invalid review state for ${fp}`);
    }
    out[fp] = state as ReviewState;
  }
  scanValue(out, "review");
  const json = JSON.stringify(out);
  assertUtf8Limit(json, TEAM_LIMITS.reviewBytes, "review");
  return JSON.parse(json) as Record<string, ReviewState>;
}

export function assertReportDtoPayload(dto: unknown): unknown {
  if (!dto || typeof dto !== "object" || Array.isArray(dto)) {
    fail("reportDto must be an object");
  }
  const parsed = parseOrThrow(ReportDtoSchema, dto, "reportDto");
  return finalizeTeamReportDto(projectTeamReportDto(parsed));
}

export function assertAllowedCollab(write: CollabWrite): CollabWrite {
  if (!write || typeof write !== "object" || Array.isArray(write)) {
    fail("collab write must be an object");
  }
  for (const key of Object.keys(write)) {
    assertAllowedKey(key);
    if (!COLLAB_KEYS.has(key)) fail(`unknown collab field ${key}`);
  }
  const out: CollabWrite = {};
  if (write.policy !== undefined) {
    out.policy = write.policy === null ? null : assertPolicyPayload(write.policy);
  }
  if (write.review !== undefined) {
    out.review = write.review === null ? null : assertReviewPayload(write.review);
  }
  if (write.reportDto !== undefined) {
    out.reportDto = write.reportDto === null ? null : assertReportDtoPayload(write.reportDto);
  }
  return out;
}

export function parseStoredPolicy(raw: string | null): AnalysisPolicy | null {
  if (raw == null) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    fail("stored policy JSON is invalid");
  }
  return assertPolicyPayload(parsed);
}

export function parseStoredReview(raw: string | null): Record<string, ReviewState> | null {
  if (raw == null) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    fail("stored review JSON is invalid");
  }
  return assertReviewPayload(parsed);
}

export function parseStoredReportDto(raw: string | null): unknown | null {
  if (raw == null) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    fail("stored reportDto JSON is invalid");
  }
  return finalizeTeamReportDto(parsed);
}
