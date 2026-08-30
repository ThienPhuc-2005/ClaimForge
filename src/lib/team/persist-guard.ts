import {
  clonePolicy,
  sanitizePolicy,
  validatePolicyPatterns,
  type AnalysisPolicy,
} from "../claimforge/policy.ts";
import { REPORT_SCHEMA_VERSION } from "../claimforge/report-dto.ts";
import { REVIEW_STATES } from "../claimforge/review.ts";
import type { ReviewState } from "../claimforge/types.ts";
import { TeamPersistError } from "./errors.ts";
import type { CollabWrite } from "./types.ts";

const COMPACT_JWT = /eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*/;
const PEM_PRIVATE = /BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY/;
const BEARER = /\bBearer\s+(?!\[redacted\])\S+/i;

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
]);

function normKey(key: string): string {
  return key.toLowerCase().replace(/[_-]/g, "");
}

function assertSafeString(value: string, path: string): void {
  if (COMPACT_JWT.test(value)) {
    throw new TeamPersistError(`forbidden compact JWT at ${path}`);
  }
  if (PEM_PRIVATE.test(value)) {
    throw new TeamPersistError(`forbidden private key at ${path}`);
  }
  if (BEARER.test(value)) {
    throw new TeamPersistError(`forbidden bearer token at ${path}`);
  }
}

function walk(value: unknown, path: string): void {
  if (value == null) return;
  if (typeof value === "string") {
    assertSafeString(value, path);
    return;
  }
  if (typeof value === "number" || typeof value === "boolean") return;
  if (Array.isArray(value)) {
    value.forEach((item, i) => walk(item, `${path}[${i}]`));
    return;
  }
  if (typeof value !== "object") return;
  const rec = value as Record<string, unknown>;
  if ("log" in rec && rec.log && typeof rec.log === "object" && "entries" in (rec.log as object)) {
    throw new TeamPersistError(`forbidden HAR log at ${path}`);
  }
  for (const [key, child] of Object.entries(rec)) {
    const nk = normKey(key);
    if (nk === "tenantid") {
      throw new TeamPersistError("tenant_id is not accepted from caller input");
    }
    if (FORBIDDEN_KEYS.has(nk) || FORBIDDEN_KEYS.has(key.toLowerCase())) {
      throw new TeamPersistError(`forbidden persist key ${key}`);
    }
    if (nk === "raw" && /jwt/i.test(path)) {
      throw new TeamPersistError(`forbidden jwt.raw at ${path}.${key}`);
    }
    if (nk === "value" && /cookie/i.test(path)) {
      throw new TeamPersistError(`forbidden cookie value at ${path}.${key}`);
    }
    walk(child, `${path}.${key}`);
  }
}

export function assertPolicyPayload(policy: unknown): AnalysisPolicy {
  if (!policy || typeof policy !== "object" || Array.isArray(policy)) {
    throw new TeamPersistError("policy must be an object");
  }
  walk(policy, "policy");
  let next: AnalysisPolicy;
  try {
    next = sanitizePolicy(clonePolicy(policy as AnalysisPolicy));
  } catch {
    throw new TeamPersistError("policy is not a valid AnalysisPolicy");
  }
  const errors = validatePolicyPatterns(next);
  if (errors.length) {
    throw new TeamPersistError(`policy regex invalid: ${errors[0]!.error}`);
  }
  return next;
}

export function assertReviewPayload(review: unknown): Record<string, ReviewState> {
  if (!review || typeof review !== "object" || Array.isArray(review)) {
    throw new TeamPersistError("review must be an object");
  }
  walk(review, "review");
  const out: Record<string, ReviewState> = {};
  for (const [fp, state] of Object.entries(review as Record<string, unknown>)) {
    if (!(REVIEW_STATES as readonly string[]).includes(state as string)) {
      throw new TeamPersistError(`invalid review state for ${fp}`);
    }
    out[fp] = state as ReviewState;
  }
  return out;
}

export function assertReportDtoPayload(dto: unknown): unknown {
  if (!dto || typeof dto !== "object" || Array.isArray(dto)) {
    throw new TeamPersistError("reportDto must be an object");
  }
  const rec = dto as Record<string, unknown>;
  if (rec.secrets !== "redacted") {
    throw new TeamPersistError("reportDto.secrets must be redacted");
  }
  if (rec.tool !== "ClaimForge") {
    throw new TeamPersistError("reportDto.tool is invalid");
  }
  if (typeof rec.schemaVersion !== "string" || !rec.schemaVersion.startsWith("report-dto")) {
    throw new TeamPersistError("reportDto.schemaVersion is invalid");
  }
  if (rec.schemaVersion !== REPORT_SCHEMA_VERSION && rec.schemaVersion !== "report-dto-1") {
    throw new TeamPersistError("reportDto.schemaVersion is not supported");
  }
  if ("aRaw" in rec || "bRaw" in rec || "requests" in rec) {
    throw new TeamPersistError("reportDto must not include capture fields");
  }
  walk(dto, "reportDto");
  return dto;
}

export function assertAllowedCollab(write: CollabWrite): CollabWrite {
  walk(write, "collab");
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
