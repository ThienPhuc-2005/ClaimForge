# ClaimForge Enterprise & Team Edition — Implementation Specification

Canonical product spec (do not duplicate into `docs/agent/`). Agent state lives in `docs/agent/`.

This file is the in-repo copy of the session-0 implementation spec. Full gates:

- Solo Offline + Team Self-hosted; deterministic core; no required AI.
- P0 before Team: evidence/policy trust, ReportDTO redaction, replay credential wipe, session/logout, forge integrity, JWKS SSRF, confidence/review, adversarial regressions.
- First coding slice (done this session): P0.1 Canonical Evidence / Policy trust boundary.

If a later commit replaces this with the full long-form spec, keep this path. Do not mark the product enterprise-ready until release gates in the full spec pass.
