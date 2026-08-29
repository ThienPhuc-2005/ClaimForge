/**
 * Revoked lab JWT `jti`s. Warm isolates keep a Map; when DATABASE_URL is set
 * (serverless/Neon) the row is also written so cold starts still reject the token.
 */

type Slot = { jtis: Map<string, number> };

function slot(): Slot {
  const g = globalThis as typeof globalThis & { __claimforgeLabRevoke?: Slot };
  if (!g.__claimforgeLabRevoke) g.__claimforgeLabRevoke = { jtis: new Map() };
  return g.__claimforgeLabRevoke;
}

function durableDb(): boolean {
  return Boolean(typeof process !== "undefined" && process.env.DATABASE_URL?.trim());
}

async function withSql<T>(fn: (sql: { query: (text: string, params?: unknown[]) => Promise<unknown[]> }) => Promise<T>): Promise<T | undefined> {
  if (!durableDb()) return undefined;
  const { getSql } = await import("../db.ts");
  const sql = await getSql();
  await sql.query(
    "CREATE TABLE IF NOT EXISTS lab_revoke (jti text PRIMARY KEY, exp bigint NOT NULL)",
  );
  return fn(sql);
}

export async function revokeJti(jti: string, exp: number): Promise<void> {
  if (!jti) return;
  slot().jtis.set(jti, exp);
  try {
    await withSql(async (sql) => {
      await sql.query(
        "INSERT INTO lab_revoke (jti, exp) VALUES ($1, $2) ON CONFLICT (jti) DO UPDATE SET exp = EXCLUDED.exp",
        [jti, exp],
      );
    });
  } catch {
    /* Map still holds this isolate */
  }
}

export async function isJtiRevoked(jti: string): Promise<boolean> {
  if (!jti) return false;
  const now = Math.floor(Date.now() / 1000);
  const local = slot().jtis.get(jti);
  if (local != null) {
    if (local < now) {
      slot().jtis.delete(jti);
      return false;
    }
    return true;
  }
  try {
    const hit = await withSql(async (sql) => {
      const rows = await sql.query("SELECT jti FROM lab_revoke WHERE jti = $1 AND exp > $2", [jti, now]);
      return rows.length > 0;
    });
    if (hit) {
      slot().jtis.set(jti, now + 7200);
      return true;
    }
  } catch {
    /* fall through */
  }
  return false;
}

export function resetRevokeState(): void {
  slot().jtis.clear();
}
