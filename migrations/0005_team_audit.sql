-- P1.4 append-only tenant audit. Additive: does not rewrite 0003 or 0004.
-- No IP, IP hash, or User-Agent columns (ADR-023: omit rather than sha256(ip)).
-- No FK to team_member: deleting a member must not erase who-changed-what.
-- UPDATE is rejected. DELETE is allowed only via tenant CASCADE.

CREATE TABLE team_audit (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES team_tenant (id) ON DELETE CASCADE,
  at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  actor_user_key TEXT NOT NULL,
  actor_role TEXT NOT NULL CHECK (actor_role IN ('owner', 'admin', 'lead', 'analyst', 'viewer')),
  action TEXT NOT NULL CHECK (action IN (
    'member.add',
    'member.role',
    'member.remove',
    'workspace.create',
    'workspace.delete',
    'collab.update'
  )),
  target_kind TEXT NOT NULL CHECK (target_kind IN ('member', 'workspace', 'collab')),
  target_id TEXT NOT NULL,
  detail_json TEXT NOT NULL,
  CHECK (char_length(target_id) BETWEEN 1 AND 256),
  CHECK (octet_length(detail_json) <= 4096)
);

CREATE INDEX team_audit_tenant_at_idx ON team_audit (tenant_id, at DESC, id DESC);

CREATE FUNCTION team_audit_append_only() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  RAISE EXCEPTION 'team_audit is append-only';
END;
$$;

CREATE TRIGGER team_audit_no_update
  BEFORE UPDATE ON team_audit
  FOR EACH ROW
  EXECUTE FUNCTION team_audit_append_only();
