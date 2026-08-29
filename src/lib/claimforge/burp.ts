import type { ActorId, CapturedRequest } from "./types.ts";
import { fromHttpMessages } from "./http.ts";

export function looksLikeBurpXml(raw: string): boolean {
  const head = raw.slice(0, 4000);
  return (
    /<\?xml|<\s*items[\s>]|<\s*item[\s>]/i.test(head) &&
    /<\s*(request|response|url|method)[\s>]/i.test(raw)
  );
}

function decodeEntities(s: string): string {
  return s
    .replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, "$1")
    .replace(/</g, "<")
    .replace(/>/g, ">")
    .replace(/"/g, '"')
    .replace(/'/g, "'")
    .replace(/&/g, "&");
}

function attrs(open: string): Record<string, string> {
  const out: Record<string, string> = {};
  const re = /([:\w.-]+)\s*=\s*"([^"]*)"/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(open))) out[m[1]!.toLowerCase()] = m[2]!;
  return out;
}

function child(xml: string, tag: string): { attr: Record<string, string>; text: string } | null {
  const re = new RegExp(`<${tag}(\\s[^>]*)?>([\\s\\S]*?)</${tag}>`, "i");
  const m = xml.match(re);
  if (!m) return null;
  return { attr: attrs(m[1] ?? ""), text: decodeEntities(m[2] ?? "").trim() };
}

function decodePayload(text: string, attr: Record<string, string>): string {
  const isB64 = /^(true|yes|1)$/i.test(attr.base64 ?? "");
  if (!isB64) return text;
  const compact = text.replace(/\s+/g, "");
  try {
    const bin = atob(compact);
    const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
    return new TextDecoder("utf-8", { fatal: false }).decode(bytes);
  } catch {
    return text;
  }
}

function parseBurpTime(s: string): number {
  const t = Date.parse(s);
  if (Number.isFinite(t)) return t;
  return Date.now();
}

function itemToRequest(itemXml: string, actor: ActorId): CapturedRequest | null {
  const url = child(itemXml, "url")?.text;
  const method = child(itemXml, "method")?.text;
  const time = child(itemXml, "time")?.text;
  const statusHint = child(itemXml, "status")?.text;
  const reqNode = child(itemXml, "request");
  const resNode = child(itemXml, "response");
  const requestText = reqNode ? decodePayload(reqNode.text, reqNode.attr) : "";
  const responseText = resNode ? decodePayload(resNode.text, resNode.attr) : "";
  const startedAt = time ? parseBurpTime(time) : Date.now();
  const parsed = fromHttpMessages(actor, requestText, responseText, startedAt, url);
  if (!parsed) return null;
  if (method) parsed.method = method.toUpperCase();
  if (statusHint && !parsed.status) parsed.status = Number(statusHint) || parsed.status;
  return parsed;
}

export function parseBurpXml(raw: string, actor: ActorId): CapturedRequest[] {
  const chunks = raw.split(/<item\b/i).slice(1);
  const out: CapturedRequest[] = [];
  for (const chunk of chunks) {
    const end = chunk.toLowerCase().lastIndexOf("</item>");
    const body = end === -1 ? chunk : chunk.slice(0, end);
    const req = itemToRequest(body, actor);
    if (req) out.push(req);
  }
  return out;
}
