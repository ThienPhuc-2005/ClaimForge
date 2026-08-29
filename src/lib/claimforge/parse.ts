import type { ActorId, CapturedRequest, HttpHeader } from "./types.ts";
import { looksLikeBurpXml, parseBurpXml } from "./burp.ts";
import { extractJwtStrings } from "./jwt.ts";
import { fromHttpMessages, nid, resetParseIds, splitUrl } from "./http.ts";
import { templatize } from "./url.ts";

export { resetParseIds, templatize };

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

function fromHarEntry(entry: Record<string, unknown>, actor: ActorId): CapturedRequest | null {
  const req = (entry.request ?? {}) as Record<string, unknown>;
  const res = (entry.response ?? {}) as Record<string, unknown>;
  const url = String(req.url ?? "");
  if (!url) return null;
  const { origin, path, query } = splitUrl(url);
  const postData = req.postData as { text?: string } | undefined;
  const content = res.content as { text?: string } | undefined;
  const started = String(entry.startedDateTime ?? "");
  const startedAt = started ? Date.parse(started) : Date.now();
  const requestHeaders = headersFromObject(req.headers);
  const responseHeaders = headersFromObject(res.headers);
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
    requestBody: postData?.text,
    status: Number(res.status ?? 0),
    statusText: String(res.statusText ?? ""),
    responseHeaders,
    responseBody: content?.text,
    timeMs: Number(entry.time ?? 0),
  };
}

export function parseHarLike(raw: string, actor: ActorId): CapturedRequest[] {
  const trimmed = raw.trim();
  if (!trimmed) return [];
  if (looksLikeBurpXml(trimmed)) {
    const items = parseBurpXml(trimmed, actor);
    if (items.length) return items;
  }
  try {
    const json = JSON.parse(trimmed) as unknown;
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
  } catch {
    /* raw HTTP */
  }
  return parseRawHttp(trimmed, actor);
}

function parseRawHttp(raw: string, actor: ActorId): CapturedRequest[] {
  const blocks = raw
    .split(/\n-{3,}\n/)
    .map((b) => b.trim())
    .filter(Boolean);
  const out: CapturedRequest[] = [];
  for (const block of blocks) {
    if (block.startsWith("{") || block.startsWith("[")) {
      out.push(...parseHarLike(block, actor));
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
