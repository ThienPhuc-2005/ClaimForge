import { SignJWT, jwtVerify, decodeProtectedHeader, decodeJwt } from "jose";
import { mintJwt } from "../claimforge/jwt.ts";
import { LAB_SECRET, LAB_USERS } from "./constants.ts";

export { LAB_SECRET, LAB_USERS };

const INVOICES: Record<number, { id: number; ownerId: string; total: number; secretLast4: string }> = {
  5512: { id: 5512, ownerId: "alice", total: 480, secretLast4: "8211" },
  8801: { id: 8801, ownerId: "bob", total: 12, secretLast4: "0007" },
};

export type LabMode = "vulnerable" | "fixed";

const denylist = new Set<string>();

function secretBytes() {
  return new TextEncoder().encode(LAB_SECRET);
}

export async function mintLabToken(sub: string, extra: Record<string, unknown> = {}): Promise<string> {
  return new SignJWT({ sub, role: "user", ...extra })
    .setProtectedHeader({ alg: "HS256", typ: "JWT" })
    .setIssuedAt()
    .setExpirationTime("2h")
    .setJti(`${sub}-${Date.now()}`)
    .sign(secretBytes());
}

interface LabUser {
  sub: string;
  email: string;
  invoices: readonly number[];
  role: string;
}

async function authenticate(req: Request, mode: LabMode): Promise<{ user: LabUser; token: string } | { error: string; status: number }> {
  const auth = req.headers.get("authorization") ?? "";
  const m = auth.match(/^Bearer\s+(\S+)/i);
  if (!m) return { error: "missing bearer", status: 401 };
  const token = m[1]!;
  if (mode === "fixed" && denylist.has(token)) return { error: "revoked", status: 401 };
  try {
    const header = decodeProtectedHeader(token);
    const alg = String(header.alg ?? "").toLowerCase();
    if (mode === "fixed") {
      if (alg === "none" || alg === "n0ne") return { error: "alg none rejected", status: 401 };
      const { payload } = await jwtVerify(token, secretBytes(), { algorithms: ["HS256"] });
      const sub = String(payload.sub ?? "");
      const u = Object.values(LAB_USERS).find((x) => x.sub === sub);
      if (!u) return { error: "unknown sub", status: 401 };
      return { user: { sub: u.sub, email: u.email, invoices: u.invoices, role: String(payload.role ?? "user") }, token };
    }
    // Vulnerable: accept alg=none and skip HMAC.
    if (alg === "none" || alg === "n0ne" || !token.split(".")[2]) {
      const payload = decodeJwt(token);
      const sub = String(payload.sub ?? "");
      return {
        user: {
          sub,
          email: `${sub}@lab.test`,
          invoices: Object.values(LAB_USERS).find((x) => x.sub === sub)?.invoices ?? [],
          role: String(payload.role ?? "user"),
        },
        token,
      };
    }
    try {
      const { payload } = await jwtVerify(token, secretBytes(), { algorithms: ["HS256"] });
      const sub = String(payload.sub ?? "");
      const u = Object.values(LAB_USERS).find((x) => x.sub === sub);
      return {
        user: {
          sub,
          email: u?.email ?? `${sub}@lab.test`,
          invoices: u?.invoices ?? [],
          role: String(payload.role ?? "user"),
        },
        token,
      };
    } catch {
      const payload = decodeJwt(token);
      const sub = String(payload.sub ?? "anon");
      return {
        user: { sub, email: `${sub}@lab.test`, invoices: [], role: String(payload.role ?? "user") },
        token,
      };
    }
  } catch {
    return { error: "bad token", status: 401 };
  }
}

function json(status: number, body: unknown, extra: HeadersInit = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", ...extra },
  });
}

export function labModeOf(req: Request): LabMode {
  const h = (req.headers.get("x-lab-mode") ?? new URL(req.url).searchParams.get("mode") ?? "vulnerable").toLowerCase();
  return h === "fixed" ? "fixed" : "vulnerable";
}

export async function handleLabRequest(req: Request): Promise<Response> {
  const url = new URL(req.url);
  const path = url.pathname.replace(/\/+$/, "") || "/";
  const mode = labModeOf(req);
  const method = req.method.toUpperCase();

  if (path === "/api/lab/health" && method === "GET") {
    return json(200, { ok: true, mode, labs: ["bola", "jwt", "logout"] });
  }

  if (path === "/api/lab/login" && method === "POST") {
    let body: { email?: string; password?: string } = {};
    try {
      body = (await req.json()) as { email?: string; password?: string };
    } catch {
      body = {};
    }
    const u = Object.values(LAB_USERS).find((x) => x.email === body.email && x.password === body.password);
    if (!u) return json(401, { error: "invalid credentials" });
    const token = await mintLabToken(u.sub);
    denylist.delete(token);
    return json(200, { token, user: { id: u.sub, role: "user" } });
  }

  if (path === "/api/lab/logout" && method === "POST") {
    const auth = await authenticate(req, mode);
    if ("error" in auth) return json(auth.status, { error: auth.error });
    if (mode === "fixed") denylist.add(auth.token);
    return json(200, { ok: true, revoked: mode === "fixed" });
  }

  if (path === "/api/lab/me" && method === "GET") {
    const auth = await authenticate(req, mode);
    if ("error" in auth) return json(auth.status, { error: auth.error });
    return json(200, { id: auth.user.sub, email: auth.user.email, invoices: auth.user.invoices, role: auth.user.role });
  }

  const inv = path.match(/^\/api\/lab\/invoices\/(\d+)$/);
  if (inv && method === "GET") {
    const auth = await authenticate(req, mode);
    if ("error" in auth) return json(auth.status, { error: auth.error });
    const id = Number(inv[1]);
    const row = INVOICES[id];
    if (!row) return json(404, { error: "not found" });
    if (mode === "fixed" && row.ownerId !== auth.user.sub) return json(403, { error: "forbidden" });
    return json(200, row);
  }

  if (path === "/api/lab/catalog/9" && method === "GET") {
    return json(200, { id: 9, visibility: "public", title: "Summer" });
  }

  if (path === "/api/lab/admin/users" && method === "GET") {
    const auth = await authenticate(req, mode);
    if ("error" in auth) return json(auth.status, { error: auth.error });
    if (auth.user.role !== "admin") return json(403, { error: "forbidden" });
    return json(200, { users: Object.values(LAB_USERS).map((u) => ({ id: u.sub, email: u.email })) });
  }

  if (path === "/api/lab/users/me" && method === "PATCH") {
    const auth = await authenticate(req, mode);
    if ("error" in auth) return json(auth.status, { error: auth.error });
    let body: Record<string, unknown> = {};
    try {
      body = (await req.json()) as Record<string, unknown>;
    } catch {
      body = {};
    }
    const role = mode === "vulnerable" ? String(body.role ?? auth.user.role) : auth.user.role;
    return json(200, { id: auth.user.sub, role });
  }

  if (path === "/api/lab/forge-none" && method === "GET") {
    const none = mintJwt({ alg: "none", typ: "JWT" }, { sub: "alice", role: "admin", is_admin: true });
    return json(200, { token: none, hint: "Replay against /api/lab/admin/users in vulnerable mode" });
  }

  return json(404, { error: "no such lab route", path });
}

export function resetLabState() {
  denylist.clear();
}
