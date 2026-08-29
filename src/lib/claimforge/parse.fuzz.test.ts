import assert from "node:assert/strict";
import { test } from "node:test";
import { parseActorInput, parseHarLike } from "./parse.ts";

function timed<T>(fn: () => T, ms = 2000): T {
  const t0 = Date.now();
  const v = fn();
  assert.ok(Date.now() - t0 < ms, "parser exceeded time budget");
  return v;
}

test("parser fuzz: garbage, incomplete JSON, and recursion bait do not throw or hang", () => {
  const seeds = [
    "",
    " ",
    "{",
    "[",
    "}",
    "null",
    "undefined",
    '{"log":',
    '{"log":{"entries":',
    '{"log":{"entries":[{',
    "GET / HTTP/1.1",
    "GET / HTTP/1.1\n\n{",
    "<items>",
    "<?xml version='1.0'?><items><item>",
    "eyJ",
    "eyJhbGciOiJub25lIn0.eyJzdWIiOiJhIn0.",
    "\0\0\0",
    "A".repeat(50_000),
    "{".repeat(2000),
    JSON.stringify({ log: { entries: Array.from({ length: 80 }, () => ({ request: { url: "https://x/a" } })) } }),
    "GET / HTTP/1.1\n\n" + JSON.stringify({ log: { entries: [] } }),
    `<items><item><url>https://x/</url><request base64="true">!!!</request></item></items>`,
    '{"request":{"method":"GET","url":"https://x/"},"response":{"status":200}}',
  ];
  for (const s of seeds) {
    const r = timed(() => parseActorInput(s, "A"));
    assert.ok(r);
    assert.ok(Array.isArray(r.requests));
    const items = timed(() => parseHarLike(s, "A"));
    assert.ok(Array.isArray(items));
  }
});

test("parser fuzz: deterministic pseudo-random buffers stay bounded", () => {
  for (let i = 0; i < 40; i++) {
    const buf = Buffer.alloc(120 + i * 17);
    for (let j = 0; j < buf.length; j++) buf[j] = (i * 19 + j * 11 + 7) % 256;
    const s = buf.toString("utf8");
    const r = timed(() => parseActorInput(s, i % 2 === 0 ? "A" : "B"));
    assert.ok(r.requests.length < 10_000);
  }
});

test("nested JSON-looking HTTP does not recurse past depth", () => {
  let inner = '{"hello":"world"}';
  for (let i = 0; i < 12; i++) {
    inner = `GET / HTTP/1.1\nHost: x\n\n${inner}`;
  }
  const r = timed(() => parseActorInput(inner, "A"));
  assert.ok(Array.isArray(r.requests));
});
