import assert from "node:assert/strict";
import { test } from "node:test";
import { parseActorInput, parseHarLike } from "./parse.ts";
import { parseBurpXml } from "./burp.ts";
import { headerValues } from "./cookies.ts";

test("HAR base64 content body is decoded", () => {
  const text = Buffer.from('{"id":5512,"ownerId":"alice"}', "utf8").toString("base64");
  const har = JSON.stringify({
    log: {
      entries: [
        {
          startedDateTime: "2026-08-29T04:00:00.000Z",
          request: { method: "GET", url: "https://shop.lab/api/invoices/5512", headers: [] },
          response: { status: 200, headers: [], content: { text, encoding: "base64" } },
        },
      ],
    },
  });
  const items = parseHarLike(har, "A");
  assert.equal(items.length, 1);
  assert.match(items[0]?.responseBody ?? "", /ownerId/);
});

test("HAR keeps multiple Set-Cookie headers", () => {
  const har = JSON.stringify({
    log: {
      entries: [
        {
          startedDateTime: "2026-08-29T04:00:00.000Z",
          request: { method: "GET", url: "https://shop.lab/api/me", headers: [] },
          response: {
            status: 200,
            headers: [
              { name: "Set-Cookie", value: "sid=aaa; Path=/; HttpOnly; Secure; SameSite=Lax" },
              { name: "Set-Cookie", value: "pref=dark; Path=/" },
            ],
            content: { text: "{}" },
          },
        },
      ],
    },
  });
  const items = parseHarLike(har, "A");
  assert.equal(headerValues(items[0]?.responseHeaders ?? [], "set-cookie").length, 2);
});

test("Burp XML base64 request decodes", () => {
  const req = Buffer.from("GET /api/invoices/5512 HTTP/1.1\r\nHost: shop.lab\r\n\r\n", "utf8").toString("base64");
  const res = Buffer.from("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"id\":5512}", "utf8").toString("base64");
  const xml = `<?xml version="1.0"?><items><item>
    <url><![CDATA[https://shop.lab/api/invoices/5512]]></url>
    <method>GET</method>
    <request base64="true">${req}</request>
    <status>200</status>
    <response base64="true">${res}</response>
  </item></items>`;
  const items = parseBurpXml(xml, "B");
  assert.equal(items.length, 1);
  assert.equal(items[0]?.path, "/api/invoices/5512");
  assert.match(items[0]?.responseBody ?? "", /5512/);
});

test("HAR postData base64 and content.base64 flag decode", () => {
  const body = Buffer.from('{"email":"alice@lab.test"}', "utf8").toString("base64");
  const text = Buffer.from('{"ok":true}', "utf8").toString("base64");
  const har = JSON.stringify({
    log: {
      entries: [
        {
          startedDateTime: "2026-08-29T04:00:00.000Z",
          request: {
            method: "POST",
            url: "https://shop.lab/api/login",
            headers: [],
            postData: { text: body, encoding: "base64" },
          },
          response: { status: 200, headers: [], content: { text, base64: true } },
        },
      ],
    },
  });
  const items = parseHarLike(har, "A");
  assert.match(items[0]?.requestBody ?? "", /alice@lab.test/);
  assert.match(items[0]?.responseBody ?? "", /ok/);
});

test("Burp XML entity-decoded URL", () => {
  const xml = `<?xml version="1.0"?><items><item>
    <url>https://shop.lab/api/invoices/5512?q=a&b=1</url>
    <method>GET</method>
    <request>GET /api/invoices/5512?q=a&b=1 HTTP/1.1\r\nHost: shop.lab\r\n\r\n</request>
    <status>200</status>
    <response>HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nok</response>
  </item></items>`;
  const items = parseBurpXml(xml, "A");
  assert.equal(items.length, 1);
  assert.match(items[0]?.url ?? "", /b=1/);
});

test("incomplete JSON does not recurse into stack overflow", () => {
  const broken = '{"log":{"entries":[{"request":{"url":"https://x/a"';
  const items = parseHarLike(broken, "A");
  assert.equal(items.length, 0);
  const a = parseActorInput(broken, "A");
  assert.match(a.error ?? "", /Actor A/);
  const b = parseActorInput('{"oops"', "B");
  assert.match(b.error ?? "", /Actor B/);
  assert.equal(a.error === b.error, false);
});

test("JSON-looking block in raw HTTP split does not infinite-loop", () => {
  const mixed = 'GET / HTTP/1.1\nHost: x\n\n\n---\n{"log":{"entries":[';
  const items = parseHarLike(mixed, "A");
  assert.ok(Array.isArray(items));
});
