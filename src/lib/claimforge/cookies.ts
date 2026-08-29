import type { ActorId, CookieRecord } from "./types.ts";

function splitSetCookie(value: string): string[] {
  // Naive split on comma only when it looks like a new cookie, not Expires=Tue, 01
  const parts: string[] = [];
  let buf = "";
  for (const chunk of value.split(/,(?=\s*[^;=]+=)/)) {
    if (!buf) buf = chunk;
    else if (/^\s*[A-Za-z]+=/.test(chunk) && !/^\s*(Mon|Tue|Wed|Thu|Fri|Sat|Sun)/i.test(chunk)) {
      parts.push(buf);
      buf = chunk;
    } else buf += "," + chunk;
  }
  if (buf) parts.push(buf);
  return parts;
}

export function parseCookieHeader(header: string, actor: ActorId): CookieRecord[] {
  return header
    .split(";")
    .map((p) => p.trim())
    .filter(Boolean)
    .map((p) => {
      const i = p.indexOf("=");
      const name = i === -1 ? p : p.slice(0, i).trim();
      const value = i === -1 ? "" : p.slice(i + 1).trim();
      return {
        actor,
        name,
        value,
        source: "request" as const,
        flags: { httpOnly: false, secure: false, sameSite: null },
        issues: [] as string[],
      };
    })
    .filter((c) => c.name && !["expires", "path", "domain", "secure", "httponly", "samesite", "max-age"].includes(c.name.toLowerCase()));
}

export function parseSetCookie(header: string, actor: ActorId): CookieRecord[] {
  return splitSetCookie(header)
    .map((raw) => raw.trim())
    .filter(Boolean)
    .map((raw) => {
      const segs = raw.split(";").map((s) => s.trim());
      const nv = segs[0] ?? "";
      const eq = nv.indexOf("=");
      const name = eq === -1 ? nv : nv.slice(0, eq);
      const value = eq === -1 ? "" : nv.slice(eq + 1);
      const flags = {
        httpOnly: false,
        secure: false,
        sameSite: null as string | null,
        path: undefined as string | undefined,
        domain: undefined as string | undefined,
        maxAge: undefined as string | undefined,
        expires: undefined as string | undefined,
      };
      for (const s of segs.slice(1)) {
        const [k, ...rest] = s.split("=");
        const key = (k ?? "").trim().toLowerCase();
        const val = rest.join("=").trim();
        if (key === "httponly") flags.httpOnly = true;
        else if (key === "secure") flags.secure = true;
        else if (key === "samesite") flags.sameSite = val || "Set";
        else if (key === "path") flags.path = val;
        else if (key === "domain") flags.domain = val;
        else if (key === "max-age") flags.maxAge = val;
        else if (key === "expires") flags.expires = val;
      }
      const issues: string[] = [];
      const sessiony = /^(sess|sid|token|auth|jwt|access|refresh|id_token)/i.test(name) || /session|auth/i.test(name);
      if (sessiony) {
        if (!flags.httpOnly) issues.push("session-like cookie missing HttpOnly");
        if (!flags.secure) issues.push("session-like cookie missing Secure");
        if (!flags.sameSite) issues.push("session-like cookie missing SameSite");
        else if (flags.sameSite.toLowerCase() === "none" && !flags.secure) issues.push("SameSite=None without Secure");
        if (flags.maxAge && Number(flags.maxAge) > 60 * 60 * 24 * 30) issues.push("Max-Age > 30 days");
      } else if (flags.sameSite && flags.sameSite.toLowerCase() === "none" && !flags.secure) {
        issues.push("SameSite=None without Secure");
      }
      return { actor, name, value, source: "set-cookie" as const, flags, issues };
    })
    .filter((c) => c.name);
}

export function headerValue(headers: { name: string; value: string }[], name: string): string | undefined {
  const n = name.toLowerCase();
  return headers.find((h) => h.name.toLowerCase() === n)?.value;
}

export function headerValues(headers: { name: string; value: string }[], name: string): string[] {
  const n = name.toLowerCase();
  return headers.filter((h) => h.name.toLowerCase() === n).map((h) => h.value);
}
