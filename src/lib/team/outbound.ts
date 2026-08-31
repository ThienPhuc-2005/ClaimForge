import {
  auditWithoutSecrets,
  CappedBodyError,
  fetchJwksDocument,
  inspectJwksUrl,
  readCappedBody,
  type InspectJwksUrl,
  type JwksAudit,
  JWKS_MAX_BYTES,
  JWKS_TIMEOUT_MS,
} from "../claimforge/jwks-fetch.ts";
import { TeamAuthError } from "./errors.ts";

export const TEAM_FETCH_TIMEOUT_MS = JWKS_TIMEOUT_MS;
export const TEAM_FETCH_MAX_BYTES = JWKS_MAX_BYTES;

export function teamOutboundPolicy(allowlist: readonly string[]) {
  return { teamMode: true as const, hostnameAllowlist: [...allowlist] };
}

export function inspectTeamOutboundUrl(raw: string, allowlist: readonly string[]): InspectJwksUrl {
  return inspectJwksUrl(raw, teamOutboundPolicy(allowlist));
}

export function requireTeamOutboundUrl(raw: string, allowlist: readonly string[]): URL {
  const gate = inspectTeamOutboundUrl(raw, allowlist);
  if (!gate.ok || !gate.url) throw new TeamAuthError("oidc is not configured");
  return gate.url;
}

function contentTypeJson(ct: string | null): boolean {
  if (!ct) return false;
  const base = ct.split(";")[0]!.trim().toLowerCase();
  return base === "application/json" || base === "application/jwt" || base.endsWith("+json");
}

function tokenAudit(
  hostname: string,
  result: JwksAudit["result"],
  extra: Partial<Omit<JwksAudit, "action" | "hostname" | "result">> = {},
): JwksAudit {
  return auditWithoutSecrets({
    action: "token-exchange",
    hostname,
    result,
    issues: extra.issues ?? [],
    status: extra.status,
    bytes: extra.bytes,
  });
}

async function readTokenBody(res: Response, maxBytes: number): Promise<Uint8Array> {
  try {
    return await readCappedBody(res, maxBytes);
  } catch (err) {
    if (err instanceof CappedBodyError || err instanceof TeamAuthError) {
      throw new TeamAuthError("token endpoint rejected the request");
    }
    throw err;
  }
}

export async function postTeamOutbound(
  rawUrl: string,
  opts: {
    allowlist: readonly string[];
    body: URLSearchParams;
    fetchImpl?: typeof fetch;
    timeoutMs?: number;
    maxBytes?: number;
    accept?: string;
  },
): Promise<{ json: unknown; audit: JwksAudit }> {
  const timeoutMs = opts.timeoutMs ?? TEAM_FETCH_TIMEOUT_MS;
  const maxBytes = opts.maxBytes ?? TEAM_FETCH_MAX_BYTES;
  const fetchImpl = opts.fetchImpl ?? fetch;
  const url = requireTeamOutboundUrl(rawUrl, opts.allowlist);
  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(), timeoutMs);
  try {
    const res = await fetchImpl(url.href, {
      method: "POST",
      redirect: "manual",
      credentials: "omit",
      headers: {
        Accept: opts.accept ?? "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: opts.body,
      signal: ac.signal,
    });
    if (res.status >= 300 && res.status < 400) {
      throw Object.assign(new TeamAuthError("token endpoint rejected the request"), {
        audit: tokenAudit(url.hostname, "denied", { status: res.status, issues: ["redirect denied"] }),
      });
    }
    if (!res.ok) {
      throw Object.assign(new TeamAuthError("token endpoint rejected the request"), {
        audit: tokenAudit(url.hostname, "error", { status: res.status, issues: [`HTTP ${res.status}`] }),
      });
    }
    if (!contentTypeJson(res.headers.get("content-type"))) {
      throw new TeamAuthError("token endpoint rejected the request");
    }
    if (!res.body) {
      throw new TeamAuthError("token endpoint rejected the request");
    }
    const buf = await readTokenBody(res, maxBytes);
    let json: unknown;
    try {
      json = JSON.parse(new TextDecoder().decode(buf));
    } catch {
      throw new TeamAuthError("token endpoint rejected the request");
    }
    return {
      json,
      audit: tokenAudit(url.hostname, "ok", { status: res.status, bytes: buf.byteLength, issues: [] }),
    };
  } catch (err) {
    if (err instanceof TeamAuthError) throw err;
    const msg = err instanceof Error ? err.message : "token endpoint rejected the request";
    const timedOut = msg === "The operation was aborted.";
    throw Object.assign(new TeamAuthError("token endpoint rejected the request"), {
      audit: tokenAudit(url.hostname, "error", { issues: [timedOut ? "timed out" : "fetch failed"] }),
    });
  } finally {
    clearTimeout(timer);
  }
}

export { fetchJwksDocument };
