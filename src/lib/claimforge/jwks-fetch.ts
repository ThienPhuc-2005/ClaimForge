export const JWKS_TIMEOUT_MS = 8_000;
export const JWKS_MAX_BYTES = 65_536;
export const JWKS_MAX_REDIRECTS = 3;

export interface JwksFetchNotice {
  hostname: string;
  protocol: string;
  href: string;
  sends: string;
  receives: string;
}

export interface JwksAudit {
  action: "jwks-fetch";
  hostname: string;
  result: "ok" | "denied" | "error";
  status?: number;
  bytes?: number;
  issues: string[];
}

export interface JwksUrlPolicy {
  teamMode?: boolean;
  hostnameAllowlist?: string[];
}

export interface InspectJwksUrl {
  ok: boolean;
  url?: URL;
  notice: JwksFetchNotice;
  issues: string[];
}

const LOCALHOST = new Set(["localhost", "127.0.0.1", "::1", "[::1]"]);

function hostOf(u: URL): string {
  return u.hostname.replace(/^\[|\]$/g, "").toLowerCase();
}

function isIpv4(host: string): number[] | null {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(host);
  if (!m) return null;
  const parts = m.slice(1).map(Number);
  if (parts.some((n) => n > 255)) return null;
  return parts;
}

function isPrivateOrLinkLocalOrMetadata(host: string): boolean {
  if (host === "169.254.169.254" || host === "metadata.google.internal" || host === "metadata") return true;
  if (host.endsWith(".internal") || host.endsWith(".local")) return true;
  const ip = isIpv4(host);
  if (!ip) return false;
  const [a, b] = ip;
  if (a === 10) return true;
  if (a === 127) return true;
  if (a === 0) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 100 && b >= 64 && b <= 127) return true;
  return false;
}

function isLoopbackHost(host: string): boolean {
  if (LOCALHOST.has(host)) return true;
  const ip = isIpv4(host);
  return Boolean(ip && ip[0] === 127);
}

export function inspectJwksUrl(raw: string, policy: JwksUrlPolicy = {}): InspectJwksUrl {
  const issues: string[] = [];
  let url: URL | undefined;
  try {
    url = new URL(raw.trim());
  } catch {
    issues.push("JWKS URL is not a valid absolute URL");
    return {
      ok: false,
      notice: {
        hostname: "",
        protocol: "",
        href: "",
        sends: "nothing",
        receives: "nothing",
      },
      issues,
    };
  }
  const host = hostOf(url);
  const notice: JwksFetchNotice = {
    hostname: host,
    protocol: url.protocol.replace(":", ""),
    href: `${url.protocol}//${url.host}${url.pathname}`,
    sends: "GET with credentials omitted (no cookies, no Authorization)",
    receives: "JWK set JSON (public keys only; not a secret)",
  };
  if (url.username || url.password) {
    issues.push("JWKS URL must not include userinfo");
  }
  if (url.protocol === "http:") {
    if (!isLoopbackHost(host)) issues.push("HTTP JWKS is only allowed for localhost / 127.0.0.1 / [::1]");
  } else if (url.protocol !== "https:") {
    issues.push("JWKS URL must be HTTPS (HTTP only for loopback)");
  }
  if (host === "169.254.169.254" || host === "metadata.google.internal" || host === "metadata") {
    issues.push("Cloud metadata endpoints are blocked");
  }
  if (policy.teamMode) {
    if (isPrivateOrLinkLocalOrMetadata(host) && !isLoopbackHost(host)) {
      issues.push("Team mode blocks private, link-local, and metadata hosts");
    }
    if (isLoopbackHost(host) && !policy.hostnameAllowlist?.some((h) => h.toLowerCase() === host)) {
      issues.push("Team mode blocks loopback unless the hostname is on the workspace allowlist");
    }
    if (policy.hostnameAllowlist?.length && !policy.hostnameAllowlist.some((h) => h.toLowerCase() === host)) {
      issues.push("Hostname is not on the workspace JWKS allowlist");
    }
  }
  return { ok: issues.length === 0, url, notice, issues };
}

export function auditWithoutSecrets(audit: JwksAudit, extras?: Record<string, string>): JwksAudit {
  const blob = JSON.stringify({ ...audit, ...extras });
  if (/eyJ[A-Za-z0-9_-]{10,}\./.test(blob) || /BEGIN (RSA |EC )?PRIVATE KEY/.test(blob)) {
    return { ...audit, issues: [...audit.issues, "refused to log secret-shaped fields"] };
  }
  return audit;
}

function contentTypeOk(ct: string | null): boolean {
  if (!ct) return false;
  const base = ct.split(";")[0]!.trim().toLowerCase();
  return (
    base === "application/json" ||
    base === "application/jwk-set+json" ||
    base.endsWith("+json")
  );
}

export async function fetchJwksDocument(
  rawUrl: string,
  opts: {
    confirmed: boolean;
    fetchImpl?: typeof fetch;
    timeoutMs?: number;
    maxBytes?: number;
    policy?: JwksUrlPolicy;
  },
): Promise<{ jwks: { keys: unknown[] }; audit: JwksAudit }> {
  const timeoutMs = opts.timeoutMs ?? JWKS_TIMEOUT_MS;
  const maxBytes = opts.maxBytes ?? JWKS_MAX_BYTES;
  const fetchImpl = opts.fetchImpl ?? fetch;
  const first = inspectJwksUrl(rawUrl, opts.policy);
  if (!first.ok || !first.url) {
    const audit = auditWithoutSecrets({
      action: "jwks-fetch",
      hostname: first.notice.hostname,
      result: "denied",
      issues: first.issues,
    });
    throw Object.assign(new Error(first.issues.join("; ") || "JWKS URL denied"), { audit });
  }
  if (!opts.confirmed) {
    const audit = auditWithoutSecrets({
      action: "jwks-fetch",
      hostname: first.notice.hostname,
      result: "denied",
      issues: ["JWKS fetch requires explicit confirmation"],
    });
    throw Object.assign(new Error("JWKS fetch requires explicit confirmation"), { audit });
  }

  let current = first.url;
  for (let hop = 0; hop <= JWKS_MAX_REDIRECTS; hop++) {
    const gate = inspectJwksUrl(current.href, opts.policy);
    if (!gate.ok || !gate.url) {
      throw Object.assign(new Error(gate.issues.join("; ") || "redirect denied"), {
        audit: auditWithoutSecrets({
          action: "jwks-fetch",
          hostname: gate.notice.hostname,
          result: "denied",
          issues: gate.issues,
        }),
      });
    }
    current = gate.url;
    const ac = new AbortController();
    const t = setTimeout(() => ac.abort(), timeoutMs);
    try {
      const res = await fetchImpl(current.href, {
        method: "GET",
        redirect: "manual",
        credentials: "omit",
        headers: { Accept: "application/json, application/jwk-set+json" },
        signal: ac.signal,
      });
      if (res.status >= 300 && res.status < 400) {
        const loc = res.headers.get("location");
        if (!loc) throw new Error("JWKS redirect missing Location");
        current = new URL(loc, current);
        continue;
      }
      if (!res.ok) {
        throw Object.assign(new Error(`JWKS HTTP ${res.status}`), {
          audit: auditWithoutSecrets({
            action: "jwks-fetch",
            hostname: hostOf(current),
            result: "error",
            status: res.status,
            issues: [`HTTP ${res.status}`],
          }),
        });
      }
      if (!contentTypeOk(res.headers.get("content-type"))) {
        throw new Error(`JWKS content-type not JSON (${res.headers.get("content-type") ?? "missing"})`);
      }
      const buf = new Uint8Array(await res.arrayBuffer());
      if (buf.byteLength > maxBytes) {
        throw new Error(`JWKS response exceeds ${maxBytes} bytes`);
      }
      const text = new TextDecoder().decode(buf);
      const parsed = JSON.parse(text) as { keys?: unknown };
      if (!parsed || !Array.isArray(parsed.keys)) {
        throw new Error("JWKS JSON must have a keys array");
      }
      return {
        jwks: { keys: parsed.keys },
        audit: auditWithoutSecrets({
          action: "jwks-fetch",
          hostname: hostOf(current),
          result: "ok",
          status: res.status,
          bytes: buf.byteLength,
          issues: [],
        }),
      };
    } catch (e) {
      if (e && typeof e === "object" && "audit" in e) throw e;
      const msg = e instanceof Error ? e.message : "JWKS fetch failed";
      throw Object.assign(new Error(msg === "The operation was aborted." ? "JWKS fetch timed out" : msg), {
        audit: auditWithoutSecrets({
          action: "jwks-fetch",
          hostname: hostOf(current),
          result: "error",
          issues: [msg],
        }),
      });
    } finally {
      clearTimeout(t);
    }
  }
  throw Object.assign(new Error("JWKS too many redirects"), {
    audit: auditWithoutSecrets({
      action: "jwks-fetch",
      hostname: hostOf(current),
      result: "denied",
      issues: ["too many redirects"],
    }),
  });
}
