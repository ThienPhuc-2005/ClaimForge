function har(entries: object[]) {
  return JSON.stringify({ log: { version: "1.2", creator: { name: "ClaimForge lab", version: "1" }, entries } }, null, 2);
}

function entry(
  t: string,
  method: string,
  url: string,
  status: number,
  reqHeaders: Record<string, string>,
  resHeaders: Record<string, string>,
  body?: string,
  reqBody?: string,
) {
  return {
    startedDateTime: t,
    time: 42,
    request: {
      method,
      url,
      headers: Object.entries(reqHeaders).map(([name, value]) => ({ name, value })),
      postData: reqBody ? { text: reqBody } : undefined,
    },
    response: {
      status,
      statusText: status === 200 ? "OK" : status === 403 ? "Forbidden" : "Error",
      headers: Object.entries(resHeaders).map(([name, value]) => ({ name, value })),
      content: { text: body ?? "", mimeType: "application/json" },
    },
  };
}

/** Unsigned JWT header {"alg":"none","typ":"JWT"} payload alice */
const ALICE_NONE =
  "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhbGljZSIsInJvbGUiOiJ1c2VyIiwidXNlcklkIjoiYWxpY2UiLCJleHAiOjk5OTk5OTk5OTl9.";

/** HS256-looking token for bob — signature is dummy, still three parts */
const BOB_HS =
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJib2IiLCJyb2xlIjoidXNlciIsInVzZXJJZCI6ImJvYiIsImV4cCI6OTk5OTk5OTk5OX0.dummysig";

export const DEMO_A_LABEL = "alice";
export const DEMO_B_LABEL = "bob";

export function demoActorA(): string {
  return har([
    entry(
      "2026-08-28T10:00:00.000Z",
      "POST",
      "https://shop.lab/api/login",
      200,
      { "Content-Type": "application/json" },
      {
        "Set-Cookie": "sid=alice-session-01; Path=/; Max-Age=7776000",
        "Content-Type": "application/json",
      },
      JSON.stringify({ token: ALICE_NONE, user: { id: "alice", role: "user" } }),
      JSON.stringify({ email: "alice@lab.test", password: "demo" }),
    ),
    entry(
      "2026-08-28T10:00:02.000Z",
      "GET",
      "https://shop.lab/api/me",
      200,
      { Authorization: `Bearer ${ALICE_NONE}`, Cookie: "sid=alice-session-01" },
      { "Content-Type": "application/json" },
      JSON.stringify({ id: "alice", email: "alice@lab.test", invoices: [5512] }),
    ),
    entry(
      "2026-08-28T10:00:04.000Z",
      "GET",
      "https://shop.lab/api/invoices/5512",
      200,
      { Authorization: `Bearer ${ALICE_NONE}` },
      { "Content-Type": "application/json" },
      JSON.stringify({ id: 5512, ownerId: "alice", total: 480, secretLast4: "8211" }),
    ),
    entry(
      "2026-08-28T10:00:08.000Z",
      "GET",
      "https://shop.lab/api/invoices/5512?access_token=" + ALICE_NONE,
      200,
      {},
      { "Content-Type": "application/json" },
      JSON.stringify({ id: 5512, ownerId: "alice", total: 480 }),
    ),
    entry(
      "2026-08-28T10:00:20.000Z",
      "POST",
      "https://shop.lab/api/token/refresh",
      200,
      { Authorization: `Bearer ${ALICE_NONE}` },
      { "Content-Type": "application/json" },
      JSON.stringify({ token: ALICE_NONE }),
    ),
    entry(
      "2026-08-28T10:00:24.000Z",
      "GET",
      "https://shop.lab/api/me",
      200,
      {
        Authorization: `Bearer ${ALICE_NONE}`,
        "X-Api-Key": "sk_lab_shop_internal_7f3a",
      },
      {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Credentials": "true",
      },
      JSON.stringify({ id: "alice", email: "alice@lab.test", invoices: [5512] }),
    ),
  ]);
}

export function demoActorB(): string {
  return har([
    entry(
      "2026-08-28T10:01:00.000Z",
      "POST",
      "https://shop.lab/api/login",
      200,
      { "Content-Type": "application/json" },
      {
        "Set-Cookie": "sid=bob-session-09; Path=/; HttpOnly; Secure; SameSite=Lax",
        "Content-Type": "application/json",
      },
      JSON.stringify({ token: BOB_HS, user: { id: "bob", role: "user" } }),
      JSON.stringify({ email: "bob@lab.test", password: "demo" }),
    ),
    entry(
      "2026-08-28T10:01:03.000Z",
      "GET",
      "https://shop.lab/api/me",
      200,
      { Authorization: `Bearer ${BOB_HS}`, Cookie: "sid=bob-session-09" },
      { "Content-Type": "application/json" },
      JSON.stringify({ id: "bob", email: "bob@lab.test", invoices: [8801] }),
    ),
    entry(
      "2026-08-28T10:01:05.000Z",
      "GET",
      "https://shop.lab/api/invoices/8801",
      200,
      { Authorization: `Bearer ${BOB_HS}` },
      { "Content-Type": "application/json" },
      JSON.stringify({ id: 8801, ownerId: "bob", total: 12 }),
    ),
    entry(
      "2026-08-28T10:01:07.000Z",
      "GET",
      "https://shop.lab/api/invoices/5512",
      200,
      { Authorization: `Bearer ${BOB_HS}` },
      { "Content-Type": "application/json" },
      JSON.stringify({ id: 5512, ownerId: "alice", total: 480, secretLast4: "8211" }),
    ),
    entry(
      "2026-08-28T10:01:09.000Z",
      "GET",
      "https://shop.lab/api/admin/users",
      403,
      { Authorization: `Bearer ${BOB_HS}` },
      { "Content-Type": "application/json" },
      JSON.stringify({ error: "forbidden" }),
    ),
    entry(
      "2026-08-28T10:01:12.000Z",
      "PATCH",
      "https://shop.lab/api/users/me",
      200,
      {
        Authorization: `Bearer ${BOB_HS}`,
        "Content-Type": "application/json",
      },
      { "Content-Type": "application/json" },
      JSON.stringify({ id: "bob", role: "admin" }),
      JSON.stringify({ role: "admin" }),
    ),
    entry(
      "2026-08-28T10:01:16.000Z",
      "GET",
      "https://shop.lab/api/debug",
      500,
      { Authorization: `Bearer ${BOB_HS}` },
      { "Content-Type": "text/plain", Server: "gunicorn/20.1.0" },
      "Traceback (most recent call last):\n  File \"/opt/shop/app.py\", line 88, in debug\n    raise RuntimeError('lab dump')\nRuntimeError: lab dump at 10.0.0.14",
    ),
    entry(
      "2026-08-28T10:01:40.000Z",
      "POST",
      "https://shop.lab/api/logout",
      204,
      { Authorization: `Bearer ${BOB_HS}` },
      {},
      "",
    ),
    entry(
      "2026-08-28T10:01:42.000Z",
      "GET",
      "https://shop.lab/api/me",
      200,
      { Authorization: `Bearer ${BOB_HS}` },
      { "Content-Type": "application/json" },
      JSON.stringify({ id: "bob", email: "bob@lab.test", invoices: [8801] }),
    ),
  ]);
}
