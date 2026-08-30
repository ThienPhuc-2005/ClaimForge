import type { ReasonCode } from "./evidence.ts";
import type { Finding, FindingConfidence, ReviewState, Severity } from "./types.ts";

export const CONFIDENCE_CLASSES: FindingConfidence[] = ["observation", "suspicion", "confirmed"];

export const REVIEW_STATES: ReviewState[] = [
  "new",
  "needs-evidence",
  "confirmed",
  "rejected",
  "accepted-risk",
  "fixed",
  "retest-passed",
  "retest-failed",
];

const SEV_RANK: Record<Severity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

export function minSeverity(a: Severity, b: Severity): Severity {
  return SEV_RANK[a] <= SEV_RANK[b] ? a : b;
}

/** Proven impact is a fact in the capture, not the finding type name. */
export interface ImpactFlags {
  crossActorRead: boolean;
  writeHonored: boolean;
  sessionAliveAfterLogout: boolean;
  secretPresent: boolean;
}

export function impactFromReasonCodes(codes: readonly ReasonCode[]): ImpactFlags {
  const has = (c: ReasonCode) => codes.includes(c);
  return {
    crossActorRead: has("CROSS_ACTOR_2XX") && has("SERVER_OWNERSHIP_PROOF"),
    writeHonored: has("MASS_ASSIGN_HONORED"),
    sessionAliveAfterLogout: has("LOGOUT_CREDENTIAL_REPLAYED"),
    secretPresent: has("SECRET_IN_CAPTURE"),
  };
}

export function impactProven(flags: ImpactFlags): boolean {
  return flags.crossActorRead || flags.writeHonored || flags.sessionAliveAfterLogout || flags.secretPresent;
}

/**
 * Observation/Suspicion never reach Critical (type name is not impact).
 * Confirmed Critical requires proven impact (trusted ownership + cross-actor 2xx, etc.).
 */
export function capSeverity(confidence: FindingConfidence, proposed: Severity, impact: ImpactFlags): Severity {
  if (confidence === "observation" || confidence === "suspicion") {
    return minSeverity(proposed, "high");
  }
  if (proposed === "critical" && !impact.crossActorRead) {
    return "high";
  }
  return proposed;
}

export function engineReviewState(confidence: FindingConfidence): ReviewState {
  return confidence === "suspicion" ? "needs-evidence" : "new";
}

export const REVIEW_TRANSITIONS: Record<ReviewState, readonly ReviewState[]> = {
  new: ["needs-evidence", "confirmed", "rejected", "accepted-risk"],
  "needs-evidence": ["new", "confirmed", "rejected", "accepted-risk"],
  confirmed: ["fixed", "rejected", "accepted-risk", "needs-evidence"],
  rejected: ["new"],
  "accepted-risk": ["new", "fixed"],
  fixed: ["retest-passed", "retest-failed", "new"],
  "retest-passed": ["new"],
  "retest-failed": ["new", "needs-evidence", "confirmed"],
};

export function canTransitionReview(from: ReviewState, to: ReviewState): boolean {
  return from === to || REVIEW_TRANSITIONS[from].includes(to);
}

export function applyReviewTransition(from: ReviewState, to: ReviewState): ReviewState {
  if (!canTransitionReview(from, to)) {
    throw new Error(`invalid review transition: ${from} -> ${to}`);
  }
  return to;
}

const ENGINE_DEFAULTS = new Set<ReviewState>(["new", "needs-evidence"]);

/** Re-analysis keeps analyst progress; engine defaults yield to stored analyst states. */
export function restoreReviewState(engineState: ReviewState, stored?: ReviewState): ReviewState {
  if (!stored) return engineState;
  if (ENGINE_DEFAULTS.has(stored)) return engineState;
  return stored;
}

export function applyReviewOverrides(findings: Finding[], overrides: Record<string, ReviewState>): Finding[] {
  return findings.map((f) => {
    const key = f.fingerprint || f.id;
    const stored = overrides[key];
    if (!stored) return f;
    return { ...f, reviewState: restoreReviewState(f.reviewState, stored) };
  });
}

export function jwtReasonCodes(kind: string, issues: string[]): ReasonCode[] {
  if (kind === "alg-none") {
    const codes: ReasonCode[] = [];
    if (issues.some((i) => /none|missing/i.test(i))) codes.push("JWT_ALG_NONE");
    if (issues.some((i) => /unsigned/i.test(i))) codes.push("JWT_UNSIGNED");
    return codes.length ? codes : ["JWT_ALG_NONE"];
  }
  if (kind === "key-injection") return ["JWT_KEY_INJECTION"];
  if (kind === "priv-role") return ["JWT_PRIVILEGED_ROLE"];
  if (kind === "lifetime") return ["JWT_LIFETIME"];
  if (kind === "iss") return ["JWT_ISS_MISSING"];
  if (kind === "aud") return ["JWT_AUD_MISSING"];
  if (kind === "sub-mismatch") return ["JWT_SUB_MISMATCH"];
  return ["CAPTURE_HEURISTIC_ONLY"];
}

export function cookieReasonCode(issue: string): ReasonCode {
  if (/HttpOnly/i.test(issue)) return "COOKIE_MISSING_HTTPONLY";
  if (/SameSite=None/i.test(issue)) return "COOKIE_SAMESITE_NONE_INSECURE";
  if (/SameSite/i.test(issue)) return "COOKIE_MISSING_SAMESITE";
  if (/Secure/i.test(issue)) return "COOKIE_MISSING_SECURE";
  if (/Max-Age/i.test(issue)) return "COOKIE_LONG_MAX_AGE";
  return "CAPTURE_HEURISTIC_ONLY";
}

export function lootReasonCode(kind: string, value: string): ReasonCode {
  if (kind === "cors" && /reflected/i.test(value)) return "CORS_REFLECTED_CREDENTIALS";
  if (kind === "cors") return "CORS_STAR_NO_CREDENTIALS";
  if (kind === "mass-assign") return "MASS_ASSIGN_HONORED";
  if (kind === "key" || kind === "secret") return "SECRET_IN_CAPTURE";
  if (kind === "stack") return "STACK_TRACE_LEAK";
  return "CAPTURE_HEURISTIC_ONLY";
}

export type FindingDraft = Omit<Finding, "id" | "reasonCodes" | "reviewState"> & {
  reasonCodes?: ReasonCode[];
  reviewState?: ReviewState;
  missingEvidence?: string[];
};

function defaultMissingEvidence(confidence: FindingConfidence, codes: ReasonCode[]): string[] | undefined {
  if (confidence !== "suspicion") return undefined;
  const miss: string[] = [];
  if (codes.includes("MISSING_TRUSTED_OWNERSHIP")) miss.push("trusted server ownership proof");
  if (codes.includes("CORS_REFLECTED_CREDENTIALS")) miss.push("cross-origin credentialed read in a browser");
  if (codes.includes("MASS_ASSIGN_HONORED")) miss.push("privileged field actually changed authorization");
  if (codes.includes("LOGOUT_CREDENTIAL_REPLAYED")) miss.push("logout 2xx on a lab host");
  if (!miss.length) miss.push("server evidence or analyst confirmation");
  return miss;
}

export function finalizeFinding(draft: FindingDraft): Omit<Finding, "id"> {
  const reasonCodes: ReasonCode[] = draft.reasonCodes?.length ? [...draft.reasonCodes] : ["CAPTURE_HEURISTIC_ONLY"];
  const impact = impactFromReasonCodes(reasonCodes);
  const confidence = draft.confidence;
  const proposed = draft.severity;
  const severity = capSeverity(confidence, proposed, impact);
  if (proposed === "critical" && severity !== "critical" && !reasonCodes.includes("IMPACT_NOT_PROVEN")) {
    reasonCodes.push("IMPACT_NOT_PROVEN");
  }
  const reviewState = draft.reviewState ?? engineReviewState(confidence);
  const missingEvidence = draft.missingEvidence ?? defaultMissingEvidence(confidence, reasonCodes);
  return {
    ...draft,
    severity,
    confidence,
    reasonCodes,
    reviewState,
    missingEvidence,
  };
}

export function reviewLabel(state: ReviewState): string {
  switch (state) {
    case "new":
      return "New";
    case "needs-evidence":
      return "Needs evidence";
    case "confirmed":
      return "Confirmed";
    case "rejected":
      return "Rejected";
    case "accepted-risk":
      return "Accepted risk";
    case "fixed":
      return "Fixed";
    case "retest-passed":
      return "Retest passed";
    case "retest-failed":
      return "Retest failed";
  }
}
