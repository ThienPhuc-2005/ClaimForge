-- P1.2 OIDC pending + opaque tenant-bound sessions.
-- Does not modify 0003. No OIDC secrets, raw tokens, or audit tables.

CREATE TABLE team_oidc_pending (
  state_hash TEXT PRIMARY KEY,
  nonce TEXT NOT NULL,
  code_challenge TEXT NOT NULL,
  verifier_ciphertext TEXT NOT NULL,
  redirect_uri TEXT NOT NULL,
  tenant_slug TEXT NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  consumed_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX team_oidc_pending_expires_idx ON team_oidc_pending (expires_at);

CREATE TABLE team_session (
  id TEXT PRIMARY KEY,
  token_hash TEXT NOT NULL UNIQUE,
  prev_token_hash TEXT,
  tenant_id TEXT NOT NULL,
  user_key TEXT NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  rotated_at TIMESTAMPTZ,
  revoked_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (tenant_id, user_key)
    REFERENCES team_member (tenant_id, user_key)
    ON DELETE CASCADE
);

CREATE INDEX team_session_member_idx ON team_session (tenant_id, user_key);
CREATE INDEX team_session_expires_idx ON team_session (expires_at);
CREATE INDEX team_session_prev_hash_idx ON team_session (prev_token_hash);
