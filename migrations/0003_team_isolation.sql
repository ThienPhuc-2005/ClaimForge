-- P1.1 tenant isolation kernel. No session, OIDC, or audit tables.
-- Composite keys keep workspace/member references inside one tenant.

CREATE TABLE team_tenant (
  id TEXT PRIMARY KEY,
  slug TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  bootstrap_actor TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE team_member (
  tenant_id TEXT NOT NULL REFERENCES team_tenant (id) ON DELETE CASCADE,
  user_key TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('owner', 'admin', 'lead', 'analyst', 'viewer')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (tenant_id, user_key)
);

CREATE INDEX team_member_user_key_idx ON team_member (user_key);

CREATE TABLE team_workspace (
  tenant_id TEXT NOT NULL REFERENCES team_tenant (id) ON DELETE CASCADE,
  id TEXT NOT NULL,
  name TEXT NOT NULL,
  created_by_user_key TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (tenant_id, id),
  FOREIGN KEY (tenant_id, created_by_user_key)
    REFERENCES team_member (tenant_id, user_key)
);

CREATE TABLE team_workspace_collab (
  tenant_id TEXT NOT NULL,
  workspace_id TEXT NOT NULL,
  policy_json TEXT,
  review_json TEXT,
  report_dto_json TEXT,
  updated_by_user_key TEXT NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (tenant_id, workspace_id),
  FOREIGN KEY (tenant_id, workspace_id)
    REFERENCES team_workspace (tenant_id, id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, updated_by_user_key)
    REFERENCES team_member (tenant_id, user_key)
);
