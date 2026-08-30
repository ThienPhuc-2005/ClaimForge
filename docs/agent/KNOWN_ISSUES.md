# Known issues

- **P0.2 gap (high):** Exporters still take workspace slices, not a redacted ReportDTO allowlist. HTML/PDF not present.
- **P0.1 gap (medium):** No policy editor UI; `DEFAULT_POLICY` only. Re-run-with-new-policy delta UI not built.
- **P0.3 gap (medium):** Replay does not strip CSRF / X-API-Key / workspace-configured credential headers yet.
- **CI (low):** `.github/workflows/ci.yml` is typecheck+lint+test:claimforge only — not full spec P4 matrix. Actions still pin `actions/checkout@v4` tags not commit SHA.
