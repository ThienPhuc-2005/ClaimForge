# Test status

- **When:** P1.3 merged on `main`. Docs handoff records `4cefe02`.
- **Branch:** `main`
- **Compared against:** `4cefe02` (`origin/main`)
- **Commands (product SHA `4cefe02`):**
  - `npm test` → **482 tests / 478 pass / 4 skip / 0 fail** on a GitHub checkout (sandbox-doc tests skip without `AGENTS.md` / `.grok/skills`). Local sandbox with those files: 482 pass / 0 skip.
  - `npm run typecheck` → pass
  - `npm run lint` → pass
  - `npm run audit:deps` → 0 high
  - `npm run build` → pass
- **CI:** [run 34 success](https://github.com/ThienPhuc-2005/ClaimForge/actions/runs/33454015932) on `4cefe02` (push `main`). typecheck + lint + `npm test` + `audit:deps` + `build`. Materializes `.grok/app-env.json` (auth-off).
- **CI vs merge:** `main` has no branch protection. Green Actions is evidence, not a merge gate (ADR-029).
- **P1.3-A3 lab (not in git):** 36/36 PASS. Chromium + Firefox cookie jars, PostgreSQL 16.6 `token_hash` only, JWT `role=superadmin` ignored, viewer/analyst escalate 403, admin cannot assign owner.
- **Browser UI:** no Team UI yet (P1.6). Members routes are API-only.
