-- P1.7 Postgres RLS defense-in-depth. Additive: does not rewrite 0003–0005.
-- PGLite accepts this DDL but does not enforce RLS (ADR-028).
-- App SQL still scopes by tenant_id. RLS fails closed when claimforge.tenant_id is unset.
-- team_tenant / team_oidc_pending / team_session stay lookup tables (slug, state_hash, token_hash).

ALTER TABLE team_member ENABLE ROW LEVEL SECURITY;
ALTER TABLE team_member FORCE ROW LEVEL SECURITY;
CREATE POLICY team_member_iso ON team_member
  FOR ALL
  USING (
    tenant_id = current_setting('claimforge.tenant_id', true)
    OR (
      current_setting('claimforge.tenant_id', true) IS NULL
      AND current_setting('claimforge.user_key', true) IS NOT NULL
      AND user_key = current_setting('claimforge.user_key', true)
    )
  )
  WITH CHECK (tenant_id = current_setting('claimforge.tenant_id', true));

ALTER TABLE team_workspace ENABLE ROW LEVEL SECURITY;
ALTER TABLE team_workspace FORCE ROW LEVEL SECURITY;
CREATE POLICY team_workspace_iso ON team_workspace
  FOR ALL
  USING (tenant_id = current_setting('claimforge.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('claimforge.tenant_id', true));

ALTER TABLE team_workspace_collab ENABLE ROW LEVEL SECURITY;
ALTER TABLE team_workspace_collab FORCE ROW LEVEL SECURITY;
CREATE POLICY team_workspace_collab_iso ON team_workspace_collab
  FOR ALL
  USING (tenant_id = current_setting('claimforge.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('claimforge.tenant_id', true));

ALTER TABLE team_audit ENABLE ROW LEVEL SECURITY;
ALTER TABLE team_audit FORCE ROW LEVEL SECURITY;
CREATE POLICY team_audit_iso ON team_audit
  FOR ALL
  USING (tenant_id = current_setting('claimforge.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('claimforge.tenant_id', true));
