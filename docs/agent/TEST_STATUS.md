# Test status

- **When:** P1.1 isolation kernel (`feat/p1-isolation-kernel`)
- **Compared against:** `f1ed912` (`main`) / docs commit `1c35541`
- **Commands:**
  - `npm test` → **408 tests / 404 pass / 4 skip / 0 fail** (GitHub-checkout shape: sandbox docs and og skill skip)
  - `npm run typecheck` → pass
  - `npm run lint` → pass
  - `npm run audit:deps` → 0 vulnerabilities (`--audit-level=high`)
  - `npm run build` → pass
- **New tests:** 21 in `src/lib/team/*.test.ts` (15 isolation + 1 persist-redacted DTO + 2 gate catalog + 4 solo/lab). Prior first-party tests still pass.
- **CI workflow:** typecheck + lint + `npm test` + `audit:deps` + `build`. Materializes `.grok/app-env.json` (auth-off). Not merge-enforced (no branch protection on `main`).
- **Browser:** not required for P1.1 (no HTTP/UI).
