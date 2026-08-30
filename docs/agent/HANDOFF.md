# ClaimForge handoff

1. **Repo:** `ThienPhuc-2005/ClaimForge` · branch `main` · **HEAD `7246f43`** (P0.1 commit). Verified base before session: `b7665b7`.
2. **Milestone:** v0.9 Core Hardening · **item:** P0.1 Canonical Evidence / Policy trust boundary (first vertical slice).
3. **Session goal:** Baseline audit + `docs/agent/` bootstrap + P0.1 trust boundary so request body / unverified JWT cannot yield BOLA `confirmed`.
4. **Done:**
   - Policy + versions + canonical evidence types (`src/lib/claimforge/policy.ts`, `evidence.ts`, `versions.ts`, `hash.ts`).
   - `ownedObjects` ignores request body/query/path; JWT identity only if `sigStatus === verified` (plus analyst labels).
   - Workspace carries `engineVersion`, `ruleVersion`, `policyVersion`, `inputHash`, `resultHash`.
   - Adversarial tests: `src/lib/claimforge/p0-trust-boundary.test.ts`.
5. **Not done:** Policy editor UI, ReportDTO/P0.2, replay credential wipe P0.3, Team/OIDC.
6. **Tests:** `npm run test:claimforge` — 92 pass. `npm run typecheck` pass. `npm run lint` pass. See `TEST_STATUS.md`.
7. **Risks:** Default policy treats analyst labels as trusted identity (needed for unsigned lab JWTs). Inventory IDs that equal any JWT subject are excluded. No policy editor yet — in-code `DEFAULT_POLICY` only.
8. **Working tree:** dirty in this sandbox (no `.git` overlay). Push required to update GitHub HEAD.
9. **Next step only:** P0.2 — Canonical ReportDTO allowlist + recursive redaction canaries (JSON/MD). Do not start Team backend.
10. **Next-session prompt:** Continue ClaimForge from repository state. Read README, threat model, `docs/agent/*`. Only implement P0.2 ReportDTO redaction boundary. Run `npm run test:claimforge` including new canary tests. Update handoff before exit.
