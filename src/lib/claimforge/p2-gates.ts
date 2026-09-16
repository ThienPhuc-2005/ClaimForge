/**
 * P2 catalog: every new detection family (BFLA, CSRF, refresh reuse, spec
 * coverage, capture truncation) has a regression test that would fail if the
 * fix is reverted. Mirrors the P0.8 gate discipline (see p0-gates.ts).
 */
export const P2_ITEMS = ["A1-BFLA", "A2-CSRF", "A3-REFRESH", "B-SPEC", "D-SCALE"] as const;
export type P2Item = (typeof P2_ITEMS)[number];

export interface P2Gate {
  id: string;
  p2: P2Item;
  bug: string;
  before: string;
  after: string;
  evidenceTest: string;
}

export const P2_GATES: P2Gate[] = [
  {
    id: "A1-bfla-confirmed",
    p2: "A1-BFLA",
    bug: "Low-privilege actor reaches an admin function",
    before: "Function-level bypass invisible; only object-level BOLA scored",
    after: "Verified non-priv role bypassing an enforced admin function is Confirmed BFLA",
    evidenceTest: "p2-bfla.test.ts:BFLA confirmed: verified non-priv role bypasses an enforced admin function",
  },
  {
    id: "A1-bfla-no-false-positive",
    p2: "A1-BFLA",
    bug: "Privileged actor on their own admin route mis-flagged",
    before: "Any 2xx on an admin path flagged",
    after: "Privileged actor and non-admin routes never fire",
    evidenceTest: "p2-bfla.test.ts:BFLA does not fire for a privileged actor on their own admin route",
  },
  {
    id: "A2-csrf-samesite-none",
    p2: "A2-CSRF",
    bug: "Cookie-auth state change with SameSite=None and no token",
    before: "CSRF exposure not scored",
    after: "SameSite=None cookie-auth mutation with no token is Suspicion (IMPACT_NOT_PROVEN)",
    evidenceTest: "p2-csrf.test.ts:CSRF suspicion: cookie-auth state change, SameSite=None, no token",
  },
  {
    id: "A2-csrf-token-and-samesite-guard",
    p2: "A2-CSRF",
    bug: "False CSRF on protected requests",
    before: "Any cookie POST flagged",
    after: "Anti-CSRF token, SameSite=Lax/Strict, or bearer auth suppress the finding",
    evidenceTest: "p2-csrf.test.ts:CSRF does not fire when a SameSite=Lax/Strict cookie protects the request",
  },
  {
    id: "A3-refresh-reuse",
    p2: "A3-REFRESH",
    bug: "Rotated refresh token accepted again",
    before: "Refresh rotation abuse not scored",
    after: "Reuse of a rotated token is Confirmed in-lab; replay without rotation is Suspicion",
    evidenceTest: "p2-refresh.test.ts:confirmed reuse-after-rotation in lab: rotated token accepted again",
  },
  {
    id: "A3-refresh-clean-rotation",
    p2: "A3-REFRESH",
    bug: "Clean rotation mis-flagged as reuse",
    before: "Every repeat refresh flagged",
    after: "A rotation where the old token is never reused produces no finding",
    evidenceTest: "p2-refresh.test.ts:clean rotation (old token never reused) produces no finding",
  },
  {
    id: "B-spec-untested-and-shadow",
    p2: "B-SPEC",
    bug: "No visibility into untested / undocumented endpoints",
    before: "Coverage vs a declared spec was impossible",
    after: "Untested declared ops and shadow endpoints are reported; JSON-only, never sends a request",
    evidenceTest: "p2-spec.test.ts:coverage: declared vs observed, untested ranked by security/write",
  },
  {
    id: "D-truncation-visible",
    p2: "D-SCALE",
    bug: "Requests beyond the per-actor cap were dropped silently",
    before: "slimActor truncated with no signal; dropped traffic looked analyzed",
    after: "Truncation is surfaced on the workspace and as a CAPTURE_TRUNCATED finding",
    evidenceTest: "p2-scale-truncation.test.ts:truncation beyond the per-actor cap is surfaced, never silent",
  },
];
