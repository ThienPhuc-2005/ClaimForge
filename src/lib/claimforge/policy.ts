import type { JwtToken } from "./types.ts";

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
  return policy.successStatuses.includes(status);
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

export function policyFingerprint(policy: AnalysisPolicy): string {
  return policy.version;
}
