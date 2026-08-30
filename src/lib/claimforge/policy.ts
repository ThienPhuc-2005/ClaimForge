import type { Finding } from "./types.ts";
import type { JwtToken } from "./types.ts";
import { fnv1a64Hex } from "./hash.ts";

export type RouteClass = "public" | "shared" | "private" | "identity" | "unknown";

export interface AnalysisPolicy {
  version: string;
  publicPathPatterns: string[];
  sharedPathPatterns: string[];
  privatePathPatterns: string[];
  identityPathPatterns: string[];
  inventoryFields: string[];
  trustedOwnershipFields: string[];
  successStatuses: number[];
  denyStatuses: number[];
  requireJwtIss: string[];
  requireJwtAud: string[];
  roleHierarchy: Record<string, string[]>;
  logoutPathPatterns: string[];
  jwksHostnameAllowlist: string[];
  jwksTeamMode: boolean;
}

export const DEFAULT_POLICY: AnalysisPolicy = {
  version: "policy-1",
  publicPathPatterns: [
    "/(public|catalog|health|status|docs|openapi|swagger|assets|static|feed|marketing|blog)\\b",
  ],
  sharedPathPatterns: [],
  privatePathPatterns: ["/(invoices|orders|files|accounts|users)\\b"],
  identityPathPatterns: ["/(me|users/me|account)\\b"],
  inventoryFields: ["invoices", "orders"],
  trustedOwnershipFields: [
    "ownerid",
    "owner_id",
    "userid",
    "user_id",
    "accountid",
    "account_id",
    "customerid",
    "customer_id",
    "owner",
  ],
  successStatuses: [200, 201, 202, 204],
  denyStatuses: [401, 403],
  requireJwtIss: [],
  requireJwtAud: [],
  roleHierarchy: {},
  logoutPathPatterns: ["/(logout|sign-?out|signoff)(/|$|\\b)"],
  jwksHostnameAllowlist: [],
  jwksTeamMode: false,
};

export function pathMatches(path: string, patterns: string[]): boolean {
  for (const p of patterns) {
    try {
      if (new RegExp(p, "i").test(path)) return true;
    } catch {
      /* skip bad pattern */
    }
  }
  return false;
}

function anyMatch(path: string, patterns: string[]): boolean {
  return pathMatches(path, patterns);
}

export function routeClass(path: string, policy: AnalysisPolicy = DEFAULT_POLICY): RouteClass {
  if (anyMatch(path, policy.identityPathPatterns)) return "identity";
  if (anyMatch(path, policy.publicPathPatterns)) return "public";
  if (anyMatch(path, policy.sharedPathPatterns)) return "shared";
  if (anyMatch(path, policy.privatePathPatterns)) return "private";
  return "unknown";
}

export function isSuccessStatus(status: number, policy: AnalysisPolicy = DEFAULT_POLICY): boolean {
  if (!policy.successStatuses.length) return status >= 200 && status < 300;
  return policy.successStatuses.includes(status);
}

export function isDenyStatus(status: number, policy: AnalysisPolicy = DEFAULT_POLICY): boolean {
  if (!policy.denyStatuses.length) return status === 401 || status === 403;
  return policy.denyStatuses.includes(status);
}

/** JWT identity is trusted only after signature verify and optional iss/aud policy. */
export function isTrustedJwtIdentity(token: JwtToken, policy: AnalysisPolicy = DEFAULT_POLICY): boolean {
  if (token.sigStatus !== "verified") return false;
  const iss = token.payload.iss;
  const aud = token.payload.aud;
  if (policy.requireJwtIss.length) {
    if (typeof iss !== "string" || !policy.requireJwtIss.includes(iss)) return false;
  }
  if (policy.requireJwtAud.length) {
    const auds = Array.isArray(aud) ? aud.map(String) : aud == null ? [] : [String(aud)];
    if (!policy.requireJwtAud.some((a) => auds.includes(a))) return false;
  }
  return true;
}

export function clonePolicy(policy: AnalysisPolicy): AnalysisPolicy {
  return {
    version: policy.version,
    publicPathPatterns: [...policy.publicPathPatterns],
    sharedPathPatterns: [...policy.sharedPathPatterns],
    privatePathPatterns: [...policy.privatePathPatterns],
    identityPathPatterns: [...policy.identityPathPatterns],
    inventoryFields: [...policy.inventoryFields],
    trustedOwnershipFields: [...policy.trustedOwnershipFields],
    successStatuses: [...policy.successStatuses],
    denyStatuses: [...policy.denyStatuses],
    requireJwtIss: [...policy.requireJwtIss],
    requireJwtAud: [...policy.requireJwtAud],
    roleHierarchy: Object.fromEntries(Object.entries(policy.roleHierarchy).map(([k, v]) => [k, [...v]])),
    logoutPathPatterns: [...policy.logoutPathPatterns],
    jwksHostnameAllowlist: [...(policy.jwksHostnameAllowlist ?? [])],
    jwksTeamMode: Boolean(policy.jwksTeamMode),
  };
}

function canonBody(policy: AnalysisPolicy): string {
  return JSON.stringify({
    publicPathPatterns: policy.publicPathPatterns,
    sharedPathPatterns: policy.sharedPathPatterns,
    privatePathPatterns: policy.privatePathPatterns,
    identityPathPatterns: policy.identityPathPatterns,
    inventoryFields: policy.inventoryFields,
    trustedOwnershipFields: policy.trustedOwnershipFields,
    successStatuses: policy.successStatuses,
    denyStatuses: policy.denyStatuses,
    requireJwtIss: policy.requireJwtIss,
    requireJwtAud: policy.requireJwtAud,
    roleHierarchy: policy.roleHierarchy,
    logoutPathPatterns: policy.logoutPathPatterns,
    jwksHostnameAllowlist: policy.jwksHostnameAllowlist ?? [],
    jwksTeamMode: Boolean(policy.jwksTeamMode),
  });
}

export function policyContentFingerprint(policy: AnalysisPolicy): string {
  return fnv1a64Hex(canonBody(policy));
}

export function policyFingerprint(policy: AnalysisPolicy): string {
  return fnv1a64Hex(`${policy.version}|${canonBody(policy)}`);
}

export function bumpPolicyVersion(current: string): string {
  const t = current.trim() || "policy-1";
  const m = /^(.*?)(\d+)$/.exec(t);
  if (m) return `${m[1]}${Number(m[2]) + 1}`;
  return `${t}-2`;
}

export function parseLineList(text: string): string[] {
  return text
    .split(/[\n,]/)
    .map((s) => s.trim())
    .filter(Boolean);
}

export function parseStatusList(text: string): number[] {
  return parseLineList(text)
    .map(Number)
    .filter((n) => Number.isInteger(n) && n >= 100 && n <= 599);
}

export function parseRoleHierarchy(text: string): Record<string, string[]> {
  const out: Record<string, string[]> = {};
  for (const line of text.split("\n")) {
    const t = line.trim();
    if (!t || t.startsWith("#")) continue;
    const idx = t.indexOf(":");
    if (idx < 0) continue;
    const role = t.slice(0, idx).trim();
    if (!role) continue;
    out[role] = t
      .slice(idx + 1)
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
  }
  return out;
}

export function formatRoleHierarchy(h: Record<string, string[]>): string {
  return Object.entries(h)
    .map(([k, v]) => `${k}: ${v.join(", ")}`)
    .join("\n");
}

export function sanitizePolicy(draft: AnalysisPolicy): AnalysisPolicy {
  const next = clonePolicy(draft);
  next.version = next.version.trim() || "policy-1";
  next.trustedOwnershipFields = next.trustedOwnershipFields.map((s) => s.toLowerCase());
  next.inventoryFields = next.inventoryFields.map((s) => s.trim()).filter(Boolean);
  next.jwksHostnameAllowlist = (next.jwksHostnameAllowlist ?? []).map((s) => s.trim().toLowerCase().replace(/\.$/, "")).filter(Boolean);
  return next;
}

/** Apply an editor draft. Bumps version when content actually changed. */
export function applyPolicyEdit(previous: AnalysisPolicy, draft: AnalysisPolicy): AnalysisPolicy {
  const next = sanitizePolicy(draft);
  if (policyContentFingerprint(previous) === policyContentFingerprint(next)) {
    return { ...next, version: previous.version };
  }
  if (next.version.trim() === previous.version.trim()) {
    next.version = bumpPolicyVersion(previous.version);
  }
  return next;
}

export function roleImplies(policy: AnalysisPolicy, holder: string, needed: string): boolean {
  if (!holder || !needed) return false;
  if (holder === needed) return true;
  const seen = new Set<string>();
  const walk = (role: string): boolean => {
    if (seen.has(role)) return false;
    seen.add(role);
    const children = policy.roleHierarchy[role] ?? [];
    return children.includes(needed) || children.some(walk);
  };
  return walk(holder);
}

export function hierarchyConfigured(policy: AnalysisPolicy): boolean {
  return Object.keys(policy.roleHierarchy).length > 0;
}

/** Superior role in the declared tree (has descendants). Empty tree falls back to name heuristics. */
export function isPrivilegedRole(policy: AnalysisPolicy, role: string): boolean {
  const r = role.trim();
  if (!r) return false;
  if (!hierarchyConfigured(policy)) return /admin|root|superuser/i.test(r);
  const kids = policy.roleHierarchy[r] ?? policy.roleHierarchy[r.toLowerCase()];
  return Boolean(kids && kids.length);
}

/** True when `to` is strictly above `from` in the declared tree. Empty tree never escalates. */
export function isPrivilegeEscalation(policy: AnalysisPolicy, fromRole: string, toRole: string): boolean {
  const from = fromRole.trim();
  const to = toRole.trim();
  if (!from || !to || from === to) return false;
  if (!hierarchyConfigured(policy)) return false;
  return roleImplies(policy, to, from) && !roleImplies(policy, from, to);
}

export const POLICY_PATTERN_FIELDS = [
  ["publicPathPatterns", "Public path patterns"],
  ["sharedPathPatterns", "Shared path patterns"],
  ["privatePathPatterns", "Private path patterns"],
  ["identityPathPatterns", "Identity path patterns"],
  ["logoutPathPatterns", "Logout path patterns"],
] as const;

export interface PolicyPatternError {
  field: string;
  label: string;
  pattern: string;
  error: string;
}

export function validatePolicyPatterns(policy: AnalysisPolicy): PolicyPatternError[] {
  const out: PolicyPatternError[] = [];
  for (const [field, label] of POLICY_PATTERN_FIELDS) {
    for (const pattern of policy[field]) {
      try {
        void new RegExp(pattern, "i");
      } catch (e) {
        out.push({
          field,
          label,
          pattern,
          error: e instanceof Error ? e.message : "invalid regular expression",
        });
      }
    }
  }
  return out;
}

/** Apply is refused when any path pattern cannot compile. */
export function policyApplyDecision(
  draft: AnalysisPolicy,
): { apply: true; errors: [] } | { apply: false; errors: PolicyPatternError[] } {
  const errors = validatePolicyPatterns(draft);
  return errors.length ? { apply: false, errors } : { apply: true, errors: [] };
}

export type PolicyRerunKind = "added" | "removed" | "changed";

export interface PolicyRerunChange {
  kind: PolicyRerunKind;
  fingerprint: string;
  title: string;
  before?: { severity: string; confidence: string };
  after?: { severity: string; confidence: string };
}

export function diffFindingSets(prev: Finding[], next: Finding[]): PolicyRerunChange[] {
  const a = new Map(prev.map((f) => [f.fingerprint || f.id, f]));
  const b = new Map(next.map((f) => [f.fingerprint || f.id, f]));
  const out: PolicyRerunChange[] = [];
  for (const [fp, f] of b) {
    const old = a.get(fp);
    if (!old) {
      out.push({
        kind: "added",
        fingerprint: fp,
        title: f.title,
        after: { severity: f.severity, confidence: f.confidence },
      });
      continue;
    }
    if (old.severity !== f.severity || old.confidence !== f.confidence) {
      out.push({
        kind: "changed",
        fingerprint: fp,
        title: f.title,
        before: { severity: old.severity, confidence: old.confidence },
        after: { severity: f.severity, confidence: f.confidence },
      });
    }
  }
  for (const [fp, f] of a) {
    if (!b.has(fp)) {
      out.push({
        kind: "removed",
        fingerprint: fp,
        title: f.title,
        before: { severity: f.severity, confidence: f.confidence },
      });
    }
  }
  return out;
}
