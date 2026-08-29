import type { CapturedRequest, LootItem, SurfaceRow, Wordlists } from "./types.ts";
import { headerValue } from "./cookies.ts";
import { pathIds } from "./ids.ts";

const SECRET_KEY = /^(password|passwd|secret|api_?key|client_secret|access_token|refresh_token|auth_token|private_key)$/i;
const MASS = /^(role|roles|is_?admin|admin|privilege|permissions|price|amount|user_?id|account_?id)$/i;

function redact(v: string): string {
  if (v.length <= 12) return v;
  return `${v.slice(0, 4)}…${v.slice(-4)}`;
}

function walkSecrets(value: unknown, into: { key: string; value: string }[], depth = 0) {
  if (depth > 8 || value == null) return;
  if (Array.isArray(value)) {
    for (const v of value) walkSecrets(v, into, depth + 1);
    return;
  }
  if (typeof value === "object") {
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      if (typeof v === "string" && SECRET_KEY.test(k) && v.length > 2) into.push({ key: k, value: v });
      walkSecrets(v, into, depth + 1);
    }
  }
}

function jsonBody(text?: string): unknown {
  if (!text) return null;
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

export function harvestLoot(requests: CapturedRequest[]): LootItem[] {
  const out: LootItem[] = [];
  const seen = new Set<string>();
  const add = (item: LootItem) => {
    const k = item.kind + item.label + item.where;
    if (seen.has(k)) return;
    seen.add(k);
    out.push(item);
  };

  for (const req of requests) {
    const where = `${req.actor} ${req.method} ${req.path}`;
    for (const blob of [req.requestBody, req.responseBody]) {
      const hits: { key: string; value: string }[] = [];
      walkSecrets(jsonBody(blob), hits);
      for (const h of hits) {
        add({
          kind: h.key.toLowerCase().includes("password") ? "secret" : "key",
          severity: "high",
          label: h.key,
          value: redact(h.value),
          where,
          actor: req.actor,
        });
      }
    }

    const api = headerValue(req.requestHeaders, "x-api-key") ?? headerValue(req.requestHeaders, "api-key");
    if (api) {
      add({
        kind: "key",
        severity: "high",
        label: "X-Api-Key",
        value: redact(api),
        where,
        actor: req.actor,
      });
    }

    const acao = headerValue(req.responseHeaders, "access-control-allow-origin");
    const cred = headerValue(req.responseHeaders, "access-control-allow-credentials");
    const authed = Boolean(
      headerValue(req.requestHeaders, "authorization") || headerValue(req.requestHeaders, "cookie"),
    );
    if (req.method !== "OPTIONS" && acao) {
      const star = acao.trim() === "*";
      const credOn = Boolean(cred && /true/i.test(cred));
      // * without credentials on a public GET is normal. Flag reflected/star+creds or * on authed JSON.
      if (star && credOn) {
        add({
          kind: "cors",
          severity: "high",
          label: "CORS",
          value: `* with credentials on ${req.origin || req.path}`,
          where: req.origin || where,
          actor: req.actor,
        });
      } else if (star && authed && req.status >= 200 && req.status < 300) {
        add({
          kind: "cors",
          severity: "medium",
          label: "CORS",
          value: `* on authenticated ${req.method} ${req.template}`,
          where: req.origin || where,
          actor: req.actor,
        });
      }
    }

    const body = `${req.responseBody ?? ""}\n${req.requestBody ?? ""}`;
    if (/traceback \(most recent|at [a-zA-Z0-9_.]+\(|Exception in thread|NullPointerException|stack trace/i.test(body)) {
      add({
        kind: "stack",
        severity: "medium",
        label: "Stack trace / debug",
        value: body.slice(0, 160).replace(/\s+/g, " "),
        where,
        actor: req.actor,
      });
    }

    if (/\b10\.\d+\.\d+\.\d+\b|\b192\.168\.\d+\.\d+\b|\b172\.(1[6-9]|2\d|3[0-1])\.\d+\.\d+\b/.test(body)) {
      add({
        kind: "internal",
        severity: "low",
        label: "Internal IP in body",
        value: "RFC1918 address leaked",
        where,
        actor: req.actor,
      });
    }

    if (/^(POST|PUT|PATCH)$/.test(req.method) && !/\/(login|signin|sign-up|register|token|refresh|logout)\b/i.test(req.path)) {
      const parsed = jsonBody(req.requestBody);
      const resBody = jsonBody(req.responseBody);
      if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
        const keys = Object.keys(parsed as object).filter((k) => MASS.test(k));
        const honored = keys.filter((k) => {
          if (!resBody || typeof resBody !== "object" || Array.isArray(resBody)) return false;
          const sent = (parsed as Record<string, unknown>)[k];
          const got = (resBody as Record<string, unknown>)[k];
          return got !== undefined && String(got) === String(sent);
        });
        if (honored.length && req.status >= 200 && req.status < 300) {
          add({
            kind: "mass-assign",
            severity: "high",
            label: `Mass-assign honored: ${honored.join(", ")}`,
            value: honored.join(", "),
            where,
            actor: req.actor,
          });
        }
      }
    }
  }
  return out;
}

export function buildWordlists(requests: CapturedRequest[], idsA: string[], idsB: string[]): Wordlists {
  const emails = new Set<string>();
  const roles = new Set<string>();
  const hosts = new Set<string>();
  const ids = new Set<string>([...idsA, ...idsB]);
  for (const req of requests) {
    if (req.origin) hosts.add(req.origin);
    for (const id of pathIds(req.path)) ids.add(id);
    const blob = `${req.requestBody ?? ""} ${req.responseBody ?? ""}`;
    for (const m of blob.matchAll(/[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}/g)) emails.add(m[0]);
    for (const m of blob.matchAll(/"(?:role|roles)"\s*:\s*"([^"]+)"/g)) roles.add(m[1]!);
  }
  return {
    ids: [...ids].slice(0, 200),
    emails: [...emails].slice(0, 100),
    roles: [...roles],
    hosts: [...hosts],
  };
}

export function buildSurface(requests: CapturedRequest[]): SurfaceRow[] {
  const map = new Map<string, SurfaceRow>();
  for (const req of requests) {
    if (req.method === "PASTE") continue;
    const k = `${req.method} ${req.template}`;
    const row = map.get(k) ?? {
      method: req.method,
      template: req.template,
      hosts: [],
      statuses: [],
      actors: [],
      auth: false,
      interesting: [],
    };
    if (req.origin && !row.hosts.includes(req.origin)) row.hosts.push(req.origin);
    if (!row.statuses.includes(req.status)) row.statuses.push(req.status);
    if (!row.actors.includes(req.actor)) row.actors.push(req.actor);
    if (headerValue(req.requestHeaders, "authorization") || headerValue(req.requestHeaders, "cookie")) row.auth = true;
    if (/admin|debug|internal|graphql|swagger|health|actuator/i.test(req.path) && !row.interesting.includes("sensitive-path")) {
      row.interesting.push("sensitive-path");
    }
    map.set(k, row);
  }
  return [...map.values()].sort((a, b) => a.template.localeCompare(b.template));
}

export function bearerOf(req: CapturedRequest): string | undefined {
  const h = headerValue(req.requestHeaders, "authorization");
  const m = h?.match(/^Bearer\s+(\S+)/i);
  return m?.[1];
}
