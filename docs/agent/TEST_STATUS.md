# Test status

- **When:** P1.5 on `feat/p1.5-collab-http` (not merged). Stacked on P1.4 `83059bb`.
- **Branch:** `feat/p1.5-collab-http` (from `feat/p1.4-audit` / `main` `944f81b`)
- **Commands (this branch):**
  - `npm test` — expect **503 tests / 499 pass / 4 skip / 0 fail** on a GitHub checkout (sandbox-doc tests skip without `AGENTS.md` / `.grok/skills`). P1.5 adds 10 tests vs P1.4 493.
  - `npm run typecheck` → pass
  - `npm run lint` → pass
  - `npm run audit:deps` → 0 high
  - `npm run build` → pass
- **CI:** wait for Actions on the draft PR. Green is evidence, not a merge gate (ADR-029).
- **Browser UI:** no Team UI yet (P1.6). Workspaces, collab, audit, and members routes are API-only.
