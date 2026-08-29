import type { ActorId, CapturedRequest, HttpHeader } from "./types.ts";
import { templatize } from "./url.ts";

let seq = 0;
export function nid(prefix: string) {
  seq += 1;
  return `${prefix}-${seq}`;
}

export function resetParseIds() {
  seq = 0;
}

export function splitUrl(url: string): { origin: string; path: string; query: Record<string, string> } {
  try {
    const u = new URL(url, "https://capture.local");
    const query: Record<string, string> = {};
    u.searchParams.forEach((v, k) => {
      query[k] = v;
    });
    const origin = url.startsWith("http") ? u.origin : "";
    return { origin, path: u.pathname || "/", query };
  } catch {
    const q = url.indexOf("?");
    const path = q === -1 ? url : url.slice(0, q);
    return { origin: "", path: path || "/", query: {} };
  }
}

function headerLines(lines: string[]): HttpHeader[] {
  const headers: HttpHeader[] = [];
  for (const line of lines) {
    const i = line.indexOf(":");
    if (i > 0) headers.push({ name: line.slice(0, i).trim(), value: line.slice(i + 1).trim() });
  }
  return headers;
}

export function parseRequestText(text: string): {
  method: string;
  target: string;
  headers: HttpHeader[];
  body?: string;
} | null {
  const trimmed = text.replace(/^\uFEFF/, "").trim();
  if (!trimmed) return null;
  const parts = trimmed.split(/\r?\n\r?\n/);
  const head = parts[0] ?? "";
  const body = parts.slice(1).join("\n\n") || undefined;
  const lines = head.split(/\r?\n/);
  const m = (lines[0] ?? "").match(/^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(\S+)/i);
  if (!m) return null;
  return {
    method: (m[1] ?? "GET").toUpperCase(),
    target: m[2] ?? "/",
    headers: headerLines(lines.slice(1)),
    body,
  };
}

export function parseResponseText(text: string): {
  status: number;
  statusText: string;
  headers: HttpHeader[];
  body?: string;
} | null {
  const trimmed = text.replace(/^\uFEFF/, "").trim();
  if (!trimmed) return null;
  const parts = trimmed.split(/\r?\n\r?\n/);
  const head = parts[0] ?? "";
  const body = parts.slice(1).join("\n\n") || undefined;
  const lines = head.split(/\r?\n/);
  const sm = (lines[0] ?? "").match(/HTTP\/[\d.]+\s+(\d{3})\s*(.*)/i);
  if (!sm) return null;
  return {
    status: Number(sm[1] ?? 0),
    statusText: sm[2] ?? "",
    headers: headerLines(lines.slice(1)),
    body,
  };
}

export function fromHttpMessages(
  actor: ActorId,
  requestText: string,
  responseText: string,
  startedAt: number,
  urlHint?: string,
): CapturedRequest | null {
  const req = parseRequestText(requestText);
  const res = parseResponseText(responseText);
  if (!req && !urlHint) return null;
  const headers = req?.headers ?? [];
  const host = headers.find((h) => h.name.toLowerCase() === "host")?.value ?? "capture.local";
  const target = req?.target ?? urlHint ?? "/";
  const url = urlHint
    ? urlHint
    : target.startsWith("http")
      ? target
      : `https://${host}${target.startsWith("/") ? target : `/${target}`}`;
  const { origin, path, query } = splitUrl(url);
  return {
    id: nid(actor),
    actor,
    startedAt: Number.isFinite(startedAt) ? startedAt : Date.now(),
    method: req?.method ?? "GET",
    url,
    origin,
    path,
    template: templatize(path),
    query,
    requestHeaders: headers,
    requestBody: req?.body,
    status: res?.status ?? 0,
    statusText: res?.statusText ?? "",
    responseHeaders: res?.headers ?? [],
    responseBody: res?.body,
    timeMs: 0,
  };
}
