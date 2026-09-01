# Test status

- **When:** P1.6 held as draft (user pick: keep PR nháp). Not merged.
- **Branch:** `feat/p1.6-team-ui` `914eb27` (stacked on P1.5 `9e3c4ee` / P1.4 `83059bb` / `main` `944f81b`)
- **Commands (this branch):**
  - `npm test` — expect **509 tests / 505 pass / 4 skip / 0 fail** on a GitHub checkout (sandbox-doc tests skip). P1.6 adds 6 tests vs P1.5 503.
  - `npm run typecheck` → pass
  - `npm run lint` → pass
  - `npm run audit:deps` → 0 high
  - `npm run build` → pass
- **CI (evidence, not a merge gate, ADR-029):**
  - P1.4 [PR #4](https://github.com/ThienPhuc-2005/ClaimForge/pull/4) [run 36 success](https://github.com/ThienPhuc-2005/ClaimForge/actions/runs/33464637787)
  - P1.5 [PR #5](https://github.com/ThienPhuc-2005/ClaimForge/pull/5) [run 37 success](https://github.com/ThienPhuc-2005/ClaimForge/actions/runs/33466195709)
  - P1.6 [PR #6](https://github.com/ThienPhuc-2005/ClaimForge/pull/6) A [run 38](https://github.com/ThienPhuc-2005/ClaimForge/actions/runs/33470935582) / B [run 39 success](https://github.com/ThienPhuc-2005/ClaimForge/actions/runs/33470971472)
- **Browser UI:** More → Team is API-backed inspect. Primary tabs unchanged.
