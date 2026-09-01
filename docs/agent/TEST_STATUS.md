# Test status

- **When:** P1.4–P1.6 on `main`. A-lab (user pick 2 / typed `22`) ran sandbox-only. No product commit after squash `1be6d07`.
- **Product SHA:** `1be6d07` (`feat(p1.4-p1.6): audit, collab HTTP, and More Team inspect view (#6)`). This docs commit is handoff only.
- **Commands (GitHub checkout of `main`):**
  - `npm test` — expect **509 tests / 505 pass / 4 skip / 0 fail** (sandbox-doc tests skip).
  - `npm run typecheck` → pass
  - `npm run lint` → pass
  - `npm run audit:deps` → 0 high
  - `npm run build` → pass
- **CI (evidence, not a merge gate, ADR-029):**
  - Product squash on `main` [run 41 success](https://github.com/ThienPhuc-2005/ClaimForge/actions/runs/33500312474)
  - Pre-merge: P1.4 [run 36](https://github.com/ThienPhuc-2005/ClaimForge/actions/runs/33464637787); P1.5 [run 37](https://github.com/ThienPhuc-2005/ClaimForge/actions/runs/33466195709); P1.6 [run 39](https://github.com/ThienPhuc-2005/ClaimForge/actions/runs/33470971472) / handoff [run 40](https://github.com/ThienPhuc-2005/ClaimForge/actions/runs/33498541593)
- **Browser UI:** More → Team is API-backed inspect. Primary tabs unchanged.
- **A-lab (sandbox-only, not in git):** Chromium + Postgres **27/27 pass**. Firefox launch skipped (host GTK). P1.3 A3 remains the last dual-browser lab.
