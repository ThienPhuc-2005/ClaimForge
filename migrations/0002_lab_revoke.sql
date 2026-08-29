-- Lab JWT jti denylist (Fixed victim lab logout). Unowned; TTL via exp epoch seconds.
CREATE TABLE IF NOT EXISTS lab_revoke (
  jti TEXT PRIMARY KEY,
  exp BIGINT NOT NULL
);
