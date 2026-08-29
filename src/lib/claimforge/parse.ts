import type { ActorId, CapturedRequest, HttpHeader } from "./types.ts";
import { looksLikeBurpXml, parseBurpXml } from "./burp.ts";
import { extractJwtStrings } from "./jwt.ts";
import { fromHttpMessages, nid, resetParseIds, splitUrl } from "./http.ts";
import { templatize } from "./url.ts";
import { headerValue, headerValues } from "./cookies.ts";

export { resetParseIds, templatize };

const MAX_PARSE_DEPTH = 8;

function isJsonish(s: string): boolean {
  const t = s.trimStart();
  return t.startsWith("{") || t.startsWith("[");
}

function headersFromObject(h: unknown): HttpHeader[] {
  if (!h) return [];
  if (Array.isArray(h)) {
    return h
      .map((x) => {
        if (x && typeof x === "object" && "name" in x && "value" in x) {
          return { name: String((x as { name: unknown }).name), value: String((x as { value: unknown }).value) };
        }
        return null;
      })
      .filter((x): x is HttpHeader => x !== null);
  }
  if (typeof h === "object") {
    return Object.entries(h as Record<string, unknown>).map(([name, value]) => ({
      name,
      value: Array.isArray(value) ? value.map(String).join(", ") : String(value),
    }));
  }
  return [];
}

function decodeMaybeBase64(text: string | undefined, encoding?: string): string | undefined {
  if (text == null || text === "") return text;
  const enc = (encoding ?? "").toLowerCase();
  if (enc !== "base64" && enc !== "true" && enc !== "1") return text;
  const compact = text.replace(/\s+/g, "");
  try {
    const bin = atob(compact.replace(/-/g, "+").replace(/_/g, "/"));
    const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
    return new TextDecoder("utf-8", { fatal: false }).decode(bytes);
  } catch {
    return text;
  }
}

function harText(
  node: { text?: string; encoding?: string; base64?: boolean | string } | undefined,
): string | undefined {
  if (!node) return undefined;
  const flag = node.base64 === true || node.base64 === "true" || node.base64 === "1";
  return decodeMaybeBase64(node.text, flag ? "base64" : node.encoding);
}

function fromHarEntry(entry: Record<string, unknown>, actor: ActorId): CapturedRequest | null {
  const req = (entry.request ?? {}) as Record<string, unknown>;
  const res = (entry.response ?? {}) as Record<string, unknown>;
  const url = String(req.url ?? "");
  if (!url) return null;
  const { origin, path, query } = splitUrl(url);
  const postData = req.postData as { text?: string; encoding?: string; base64?: boolean | string } | undefined;
  const content = res.content as { text?: string; encoding?: string; base64?: boolean | string } | undefined;
  const started = String(entry.startedDateTime ?? "");
  const startedAt = started ? Date.parse(started) : Date.now();
  let requestHeaders = headersFromObject(req.headers);
  let responseHeaders = headersFromObject(res.headers);

  const reqCookies = req.cookies as { name?: string; value?: string }[] | undefined;
  if (Array.isArray(reqCookies) && reqCookies.length && !headerValue(requestHeaders, "cookie")) {
    const ck = reqCookies
      .filter((c) => c?.name)
      .map((c) => `${c.name}=${c.value ?? ""}`)
      .join("; ");
    if (ck) requestHeaders = [...requestHeaders, { name: "Cookie", value: ck }];
  }
  const resCookies = res.cookies as
    | { name?: string; value?: string; httpOnly?: boolean; secure?: boolean; sameSite?: string; path?: string }[]
    | undefined;
  if (Array.isArray(resCookies) && resCookies.length && !headerValues(responseHeaders, "set-cookie").length) {
    for (const c of resCookies) {
      if (!c?.name) continue;
      const parts = [`${c.name}=${c.value ?? ""}`];
      if (c.path) parts.push(`Path=${c.path}`);
      if (c.httpOnly) parts.push("HttpOnly");
      if (c.secure) parts.push("Secure");
      if (c.sameSite) parts.push(`SameSite=${c.sameSite}`);
      responseHeaders = [...responseHeaders, { name: "Set-Cookie", value: parts.join("; ") }];
    }
  }

  return {
    id: nid(actor),
    actor,
    startedAt: Number.isFinite(startedAt) ? startedAt : Date.now(),
    method: String(req.method ?? "GET").toUpperCase(),
    url,
    origin,
    path,
    template: templatize(path),
    query,
    requestHeaders,
    requestBody: harText(postData),
    status: Number(res.status ?? 0),
    statusText: String(res.statusText ?? ""),
    responseHeaders,
    responseBody: harText(content),
    timeMs: Number(entry.time ?? 0),
  };
}

function entriesFromJson(json: unknown, actor: ActorId): CapturedRequest[] | null {
  const log = (json as { log?: { entries?: unknown[] } }).log;
  const entries = log?.entries ?? (Array.isArray(json) ? json : null);
  if (Array.isArray(entries)) {
    return entries
      .map((e) => (e && typeof e === "object" ? fromHarEntry(e as Record<string, unknown>, actor) : null))
      .filter((x): x is CapturedRequest => x !== null);
  }
  if (json && typeof json === "object" && "request" in (json as object)) {
    const one = fromHarEntry(json as Record<string, unknown>, actor);
    return one ? [one] : [];
  }
  return null;
}

/**
 * Parse HAR / Burp / raw HTTP. Incomplete JSON must not bounce into parseRawHttp
 * (that used to recurse parseHarLike ↔ parseRawHttp until the stack blew).
 */
export function parseHarLike(raw: string, actor: ActorId, depth = 0): CapturedRequest[] {
  if (depth > MAX_PARSE_DEPTH) return [];
  const trimmed = raw.trim();
  if (!trimmed) return [];
  if (looksLikeBurpXml(trimmed)) {
    const items = parseBurpXml(trimmed, actor);
    if (items.length) return items;
  }
  if (isJsonish(trimmed)) {
    try {
      const json = JSON.parse(trimmed) as unknown;
      const fromJson = entriesFromJson(json, actor);
      return fromJson ?? [];
    } catch {
      return [];
    }
  }
  return parseRawHttp(trimmed, actor, depth);
}

function parseRawHttp(raw: string, actor: ActorId, depth: number): CapturedRequest[] {
  const blocks = raw
    .split(/\n-{3,}\n/)
    .map((b) => b.trim())
    .filter(Boolean);
  const out: CapturedRequest[] = [];
  for (const block of blocks) {
    if (isJsonish(block)) {
      out.push(...parseHarLike(block, actor, depth + 1));
      continue;
    }
    const jwtOnly = extractJwtStrings(block);
    if (/^eyJ/.test(block) && jwtOnly.length && !/^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s/i.test(block)) {
      continue;
    }
    const req = parseOneHttp(block, actor);
    if (req) out.push(req);
  }
  return out;
}

function parseOneHttp(block: string, actor: ActorId): CapturedRequest | null {
  const idx = block.search(/\nHTTP\/[\d.]+\s+\d{3}/);
  const reqText = idx >= 0 ? block.slice(0, idx) : block;
  const resText = idx >= 0 ? block.slice(idx + 1) : "";
  return fromHttpMessages(actor, reqText, resText, Date.now());
}

export function parseJwtPasted(raw: string, actor: ActorId): CapturedRequest[] {
  const tokens = extractJwtStrings(raw);
  if (!tokens.length) return [];
  if (parseHarLike(raw, actor).length) return [];
  return tokens.map((t, i) => {
    const { origin, path, query } = splitUrl("https://pasted.local/jwt");
    return {
      id: nid(actor) + `-jwt${i}`,
      actor,
      startedAt: Date.now(),
      method: "PASTE",
      url: "https://pasted.local/jwt",
      origin,
      path,
      template: "/jwt",
      query,
      requestHeaders: [{ name: "Authorization", value: `Bearer ${t}` }],
      status: 0,
      statusText: "pasted",
      responseHeaders: [],
      timeMs: 0,
    };
  });
}

export interface ActorParseResult {
  requests: CapturedRequest[];
  error?: string;
}

/** Per-actor parse with a distinct error string for incomplete JSON / crashes. */
export function parseActorInput(raw: string, actor: ActorId): ActorParseResult {
  const trimmed = raw.trim();
  if (!trimmed) return { requests: [] };
  if (isJsonish(trimmed)) {
    try {
      JSON.parse(trimmed);
    } catch {
      return {
        requests: parseJwtPasted(trimmed, actor),
        error: `Actor ${actor}: capture looks like JSON but is incomplete or invalid.`,
      };
    }
  }
  try {
    const requests = [...parseHarLike(trimmed, actor), ...parseJwtPasted(trimmed, actor)];
    return { requests };
  } catch (e) {
    return {
      requests: [],
      error: `Actor ${actor}: ${e instanceof Error ? e.message : "parse failed"}`,
    };
  }
}
