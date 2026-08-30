# Test status

- **When:** 2026-08-30 session P0.1 policy editor
- **Verified base SHA:** `6c3ba6f`
- **Commands:**
  - `npm run test:claimforge` → **151 pass / 0 fail**
  - `npm run typecheck` → pass
  - `npm run lint` → pass
- **New tests:** `src/lib/claimforge/p0-policy-editor.test.ts`
- **Browser:** Load lab capture → More → Policy → mark invoices public → Apply: Critical 1→0, changelog removed BOLA / added public-shared. Reset restored Critical 1.
