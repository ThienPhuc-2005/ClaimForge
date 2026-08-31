import { bootstrapTenant, requireName, requireSlug, unlockBootstrap } from "./context.ts";
import { TeamBootstrapError, TeamError, TeamValidationError } from "./errors.ts";
import { oidcUserKey } from "./oidc-user-key.ts";
import { wrapPgPool } from "./sql.ts";
import type { TeamSql } from "./types.ts";

export type TeamBootstrapInput = {
  slug: string;
  name: string;
  issuer: string;
  sub: string;
};

export type TeamBootstrapOutput = {
  tenantId: string;
  slug: string;
  userKey: string;
};

export type TeamBootstrapSqlHandle = {
  sql: TeamSql;
  close: () => Promise<void>;
};

const REQUIRED_FLAGS = ["--slug", "--name", "--issuer", "--sub"] as const;

function flagLooksLikeSecret(flag: string): boolean {
  return /secret|token|password|passwd|credential/i.test(flag);
}

export function parseTeamBootstrapArgs(argv: string[]): TeamBootstrapInput {
  const values = new Map<string, string>();
  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if (!token || !token.startsWith("--") || token === "--") {
      throw new TeamValidationError("unexpected argument");
    }
    const eq = token.indexOf("=");
    const flag = eq === -1 ? token : token.slice(0, eq);
    if (flagLooksLikeSecret(flag)) {
      throw new TeamBootstrapError("bootstrap secret must come from the environment");
    }
    if (!(REQUIRED_FLAGS as readonly string[]).includes(flag)) {
      throw new TeamValidationError("unknown argument");
    }
    if (values.has(flag)) {
      throw new TeamValidationError("duplicate argument");
    }
    let value: string;
    if (eq !== -1) {
      value = token.slice(eq + 1);
    } else {
      const next = argv[i + 1];
      if (next === undefined || next.startsWith("--")) {
        throw new TeamValidationError("missing argument value");
      }
      value = next;
      i += 1;
    }
    values.set(flag, value);
  }
  for (const flag of REQUIRED_FLAGS) {
    if (!values.has(flag)) {
      throw new TeamValidationError(`${flag.slice(2)} is required`);
    }
  }
  return {
    slug: requireSlug(values.get("--slug")),
    name: requireName(values.get("--name")),
    issuer: values.get("--issuer")!,
    sub: values.get("--sub")!,
  };
}

export function requireOperatorBootstrapEnv(env: Record<string, string | undefined>): {
  databaseUrl: string;
  bootstrapSecret: string;
} {
  const databaseUrl = typeof env.DATABASE_URL === "string" ? env.DATABASE_URL.trim() : "";
  if (!databaseUrl) {
    throw new TeamBootstrapError("DATABASE_URL is required");
  }
  const bootstrapSecret =
    typeof env.CLAIMFORGE_TEAM_BOOTSTRAP_SECRET === "string" ? env.CLAIMFORGE_TEAM_BOOTSTRAP_SECRET : "";
  if (!bootstrapSecret) {
    throw new TeamBootstrapError("bootstrap is not configured");
  }
  return { databaseUrl, bootstrapSecret };
}

export async function assertTeamSchemaMigrated(sql: TeamSql): Promise<void> {
  let rows: { tenant: string | null; member: string | null }[];
  try {
    rows = await sql.query<{ tenant: string | null; member: string | null }>(
      "SELECT to_regclass('public.team_tenant') AS tenant, to_regclass('public.team_member') AS member",
    );
  } catch (err) {
    if (isUndefinedTable(err)) {
      throw new TeamBootstrapError("team schema is not migrated");
    }
    throw err;
  }
  if (!rows[0]?.tenant || !rows[0]?.member) {
    throw new TeamBootstrapError("team schema is not migrated");
  }
}

function isUniqueViolation(err: unknown): boolean {
  const code = err && typeof err === "object" ? (err as { code?: string }).code : undefined;
  if (code === "23505") return true;
  const message = err instanceof Error ? err.message : "";
  return /duplicate key|unique constraint/i.test(message);
}

function isUndefinedTable(err: unknown): boolean {
  const code = err && typeof err === "object" ? (err as { code?: string }).code : undefined;
  if (code === "42P01") return true;
  const message = err instanceof Error ? err.message : "";
  return /does not exist|undefined table|relation .* does not exist/i.test(message);
}

export async function bootstrapOidcOwner(
  sql: TeamSql,
  input: TeamBootstrapInput,
  bootstrapSecret: string,
): Promise<TeamBootstrapOutput> {
  await assertTeamSchemaMigrated(sql);
  const userKey = oidcUserKey(input.issuer, input.sub);
  const actor = unlockBootstrap(bootstrapSecret, bootstrapSecret);
  try {
    const result = await bootstrapTenant(sql, actor, {
      slug: input.slug,
      name: input.name,
      ownerUserKey: userKey,
    });
    return {
      tenantId: result.tenant.id,
      slug: result.tenant.slug,
      userKey: result.owner.userKey,
    };
  } catch (err) {
    if (isUniqueViolation(err)) {
      throw new TeamBootstrapError("tenant already exists");
    }
    if (isUndefinedTable(err)) {
      throw new TeamBootstrapError("team schema is not migrated");
    }
    throw err;
  }
}

export function formatBootstrapOutput(out: TeamBootstrapOutput): string {
  return JSON.stringify({
    tenantId: out.tenantId,
    slug: out.slug,
    userKey: out.userKey,
  });
}

/**
 * Operator Postgres only. Never falls back to the preview PGLite database.
 */
export async function openOperatorTeamSql(databaseUrl: string): Promise<TeamBootstrapSqlHandle> {
  const { Pool } = await import("pg");
  const pool = new Pool({ connectionString: databaseUrl, max: 1 });
  return {
    sql: wrapPgPool(pool),
    close: () => pool.end(),
  };
}

export function safeBootstrapErrorMessage(err: unknown): string {
  if (err instanceof TeamError) return err.message;
  return "bootstrap failed";
}

/** Pool teardown must not mask a committed bootstrap or a prior safe error. */
async function settleClose(close: () => Promise<void>): Promise<void> {
  try {
    await close();
  } catch {
    /* ignore — close errors can include connection strings */
  }
}

export async function runTeamBootstrap(
  argv: string[],
  env: Record<string, string | undefined>,
  deps: {
    openSql?: (databaseUrl: string) => Promise<TeamBootstrapSqlHandle>;
    log?: (line: string) => void;
    error?: (line: string) => void;
  } = {},
): Promise<number> {
  const log = deps.log ?? ((line) => {
    console.log(line);
  });
  const error = deps.error ?? ((line) => {
    console.error(line);
  });
  try {
    const input = parseTeamBootstrapArgs(argv);
    const { databaseUrl, bootstrapSecret } = requireOperatorBootstrapEnv(env);
    oidcUserKey(input.issuer, input.sub);
    unlockBootstrap(bootstrapSecret, bootstrapSecret);
    const openSql = deps.openSql ?? openOperatorTeamSql;
    const handle = await openSql(databaseUrl);
    try {
      const out = await bootstrapOidcOwner(handle.sql, input, bootstrapSecret);
      await settleClose(() => handle.close());
      log(formatBootstrapOutput(out));
      return 0;
    } catch (err) {
      await settleClose(() => handle.close());
      error(safeBootstrapErrorMessage(err));
      return 1;
    }
  } catch (err) {
    error(safeBootstrapErrorMessage(err));
    return 1;
  }
}
