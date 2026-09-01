# Test status

- **When:** P1.4–P1.6 squash-merged to `main` (user pick: merge). [#6](https://github.com/ThienPhuc-2005/ClaimForge/pull/6) merged; [#4](https://github.com/ThienPhuc-2005/ClaimForge/pull/4)/[#5](https://github.com/ThienPhuc-2005/ClaimForge/pull/5) closed as superseded.
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
- **Not run:** A-lab (Chrome + Firefox + Postgres) for P1.4–P1.6. P1.3 A3 remains the last browser lab.
