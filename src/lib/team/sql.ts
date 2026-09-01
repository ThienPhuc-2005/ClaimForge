import { randomBytes } from "node:crypto";
import type { TeamSql } from "./types.ts";

type QueryResult = { rows: unknown[] };
type Queryable = {
  query: (text: string, params?: unknown[]) => Promise<QueryResult>;
};

export type PgliteLike = Queryable & {
  transaction: <T>(fn: (tx: PgliteLike) => Promise<T>) => Promise<T>;
};

const globalRef = globalThis as typeof globalThis & {
  __teamNeonPool__?: import("pg").Pool;
  __teamNeonSql__?: TeamSql;
};

/** Wrap a PGLite instance or transaction client. Nested transactions reuse this client. */
export function wrapPglite(client: PgliteLike): TeamSql {
  const sql: TeamSql = {
    query: async <T = Record<string, unknown>>(text: string, params: unknown[] = []) => {
      const result = await client.query(text, params);
      return result.rows as T[];
    },
    transaction: (fn) => {
      if (typeof client.transaction !== "function") {
        return fn(sql);
      }
      return client.transaction((tx) => fn(wrapPglite(tx)));
    },
  };
  return sql;
}

/**
 * Wrap a checked-out node-postgres Client. Nested `transaction()` uses SAVEPOINT
 * on this same client — never a second pool connection.
 */
export function wrapPgClient(client: Queryable): TeamSql {
  const sql: TeamSql = {
    query: async <T = Record<string, unknown>>(text: string, params: unknown[] = []) => {
      const result = await client.query(text, params);
      return result.rows as T[];
    },
    transaction: async (fn) => {
      const sp = `team_sp_${randomBytes(8).toString("hex")}`;
      await client.query(`SAVEPOINT ${sp}`);
      try {
        const result = await fn(sql);
        await client.query(`RELEASE SAVEPOINT ${sp}`);
        return result;
      } catch (err) {
        try {
          await client.query(`ROLLBACK TO SAVEPOINT ${sp}`);
        } catch {
          /* keep the original error */
        }
        throw err;
      }
    },
  };
  return sql;
}

type PgPoolLike = Queryable & {
  connect: () => Promise<Queryable & { release: () => void }>;
};

/**
 * Wrap a pg Pool. Top-level `transaction()` checks out one client, BEGIN/COMMIT
 * on that client, and runs every query inside the callback on it.
 */
export function wrapPgPool(pool: PgPoolLike): TeamSql {
  const sql: TeamSql = {
    query: async <T = Record<string, unknown>>(text: string, params: unknown[] = []) => {
      const result = await pool.query(text, params);
      return result.rows as T[];
    },
    transaction: async (fn) => {
      const client = await pool.connect();
      try {
        await client.query("BEGIN");
        const tx = wrapPgClient(client);
        try {
          const result = await fn(tx);
          await client.query("COMMIT");
          return result;
        } catch (err) {
          try {
            await client.query("ROLLBACK");
          } catch {
            /* keep the original error */
          }
          throw err;
        }
      } finally {
        client.release();
      }
    },
  };
  return sql;
}

async function neonTeamSql(databaseUrl: string): Promise<TeamSql> {
  if (globalRef.__teamNeonSql__) return globalRef.__teamNeonSql__;
  const { Pool } = await import("pg");
  globalRef.__teamNeonPool__ ??= new Pool({ connectionString: databaseUrl });
  globalRef.__teamNeonSql__ = wrapPgPool(globalRef.__teamNeonPool__);
  return globalRef.__teamNeonSql__;
}

/**
 * Production Team SQL. Neon when DATABASE_URL is set (one connection per
 * transaction); otherwise the shared PGLite fallback from `@/lib/db`.
 */
export async function getTeamSql(): Promise<TeamSql> {
  const databaseUrl =
    typeof process !== "undefined" ? process.env.DATABASE_URL?.trim() : undefined;
  if (databaseUrl) return neonTeamSql(databaseUrl);
  const { getPglite } = await import("../db.ts");
  const pg = await getPglite();
  return wrapPglite(pg as unknown as PgliteLike);
}
