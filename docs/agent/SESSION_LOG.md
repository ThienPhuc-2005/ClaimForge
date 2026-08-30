# Session log

## 2026-08-30 — P0.6 JWKS network guards

- HTTPS-only except localhost HTTP. Confirm dialog. Timeout 8s, 64KiB, JSON content-type, redirect revalidation.
- Metadata/userinfo blocked. Team mode RFC1918 + allowlist.
- 125 tests green. Next: P0.7 review/confidence.

## 2026-08-30 — P0.5 forge revision machine

- Unsigned draft / Signed output / Stale output.
- Changing header/payload/alg/HMAC/PEM/JWKS/kid/iss/aud voids signed copy.
- 117 tests green. Next: P0.6 JWKS network.

## 2026-08-30 — P0.4 session/logout credential scope

- Logout revokes only credentials on that request.
- 105 tests green. Next: P0.5 forge revision machine.

## 2026-08-30 — P0.3 replay credential boundary

- Source credentials wiped, selected actor set attached.
- 101 tests green. Next: P0.4 logout/session.

## 2026-08-30 — P0.2 ReportDTO

- Allowlist ReportDTO; canaries.
- Next: P0.3 replay credentials.

## 2026-08-30 — P0.1 trust boundary + agent docs bootstrap

- Policy/evidence/hash/versions. docs/agent bootstrap.
- Next: P0.2 ReportDTO.
