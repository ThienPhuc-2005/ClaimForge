import assert from "node:assert/strict";
import { test } from "node:test";
import { parseBurpXml } from "./burp.ts";
import { analyze } from "./analyze.ts";
import { parseHarLike } from "./parse.ts";
import { mintJwt, inspectJwt } from "./jwt.ts";
import { harvestLoot } from "./loot.ts";
import { demoActorA, demoActorB } from "./demo.ts";

function b64(s: string) {
  return Buffer.from(s, "utf8").toString("base64");
}

const req = `GET /api/invoices/5512 HTTP/1.1
Host: shop.lab
Authorization: Bearer abc.def.ghi

`;
const res = `HTTP/1.1 200 OK
Content-Type: application/json

{"id":5512,"ownerId":"alice","total":480}
`;

const xml = `<?xml version="1.0"?>
<items burpVersion="2024.7">
  <item>
    <time>Fri Aug 28 10:01:07 UTC 2026</time>
    <url><![CDATA[https://shop.lab/api/invoices/5512]]></url>
    <host>shop.lab</host>
    <port>443</port>
    <protocol>https</protocol>
    <method>GET</method>
    <path>/api/invoices/5512</path>
    <request base64="true">${b64(req)}</request>
    <status>200</status>
    <response base64="true">${b64(res)}</response>
  </item>
</items>
`;

test("parses Burp Save items XML", () => {
  const items = parseBurpXml(xml, "B");
  assert.equal(items.length, 1);
  assert.equal(items[0]?.method, "GET");
  assert.equal(items[0]?.path, "/api/invoices/5512");
  assert.equal(items[0]?.status, 200);
  assert.match(items[0]?.responseBody ?? "", /ownerId/);
});

test("parseHarLike detects Burp XML", () => {
  const items = parseHarLike(xml, "A");
  assert.equal(items.length, 1);
  assert.equal(items[0]?.template, "/api/invoices/{id}");
});

test("graph marks foreign object access as bola", () => {
  const a = JSON.stringify({
    log: {
      entries: [
        {
          startedDateTime: "2026-08-28T10:00:00.000Z",
          request: {
            method: "GET",
            url: "https://shop.lab/api/invoices/5512",
            headers: [{ name: "Authorization", value: "Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiJhbGljZSJ9." }],
          },
          response: {
            status: 200,
            headers: [],
            content: { text: JSON.stringify({ id: 5512, ownerId: "alice" }) },
          },
        },
      ],
    },
  });
  const ws = analyze(a, xml, "alice", "bob");
  assert.ok(ws.graph.nodes.some((n) => n.label === "5512"));
  assert.ok(ws.graph.edges.some((e) => e.bola), "expected a BOLA access edge");
});

test("mintJwt alg none is inspectable", () => {
  const raw = mintJwt({ alg: "none", typ: "JWT" }, { sub: "alice", role: "admin" });
  const ins = inspectJwt(raw, "A", "forge");
  assert.ok(ins);
  assert.equal(ins?.alg, "none");
  assert.equal(ins?.payload.role, "admin");
});

test("demo capture yields loot, playbook, and BOLA", () => {
  const ws = analyze(demoActorA(), demoActorB(), "alice", "bob");
  assert.ok(ws.loot.some((l) => l.kind === "cors" || l.kind === "key" || l.kind === "mass-assign"));
  assert.ok(ws.paths.length >= 1);
  assert.ok(ws.replays.length >= 1);
  assert.ok(ws.findings.some((f) => f.severity === "critical"));
  const loot = harvestLoot(ws.requests);
  assert.ok(loot.length >= 1);
});
