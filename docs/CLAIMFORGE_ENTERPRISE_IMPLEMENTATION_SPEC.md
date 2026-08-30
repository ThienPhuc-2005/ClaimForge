# ClaimForge Enterprise & Team Edition — Implementation Specification

Canonical product spec (do not duplicate into `docs/agent/`). Agent state lives in `docs/agent/`.

This file is the in-repo copy of the session-0 implementation spec. Full gates:

- Solo Offline + Team Self-hosted; deterministic core; no required AI.
- P0 before Team: evidence/policy trust, ReportDTO redaction, replay credential wipe, session/logout, forge integrity, JWKS SSRF, confidence/review, adversarial regressions.
- First coding slice (done): P0.1 Canonical Evidence / Policy trust boundary through remainder P0 + CI repair.

Team architecture (P1.0) and isolation kernel (P1.1) live in [P1_TEAM_ISOLATION.md](./P1_TEAM_ISOLATION.md). Decisions ADR-017–ADR-031 in `docs/agent/DECISIONS.md`.

Do not mark the product enterprise-ready until release gates in the Team spec pass. P1.1 is isolation only: no OIDC, no Team HTTP, no capture upload.
