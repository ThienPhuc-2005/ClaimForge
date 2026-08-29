#!/usr/bin/env node
/** Fetch a URL and assert production security headers. */
const url = process.argv[2] || process.env.HEADERS_URL || "http://127.0.0.1:8081/";
const res = await fetch(url, { redirect: "manual" });
const csp = res.headers.get("content-security-policy") ?? "";
const need = [
  ["content-security-policy", /frame-ancestors 'none'/],
  ["content-security-policy", /https:\/\/grok\.com/],
  ["content-security-policy", /worker-src/],
  ["content-security-policy", /connect-src[^;]*https:/],
  ["x-content-type-options", /nosniff/i],
  ["referrer-policy", /no-referrer/i],
  ["permissions-policy", /camera=\(\)/],
  ["x-frame-options", /DENY/i],
];
const missing = [];
for (const [name, re] of need) {
  const v = res.headers.get(name) ?? "";
  if (!re.test(v)) missing.push({ name, value: v, re: String(re) });
}
if (missing.length) {
  console.error(JSON.stringify({ ok: false, url, status: res.status, missing, csp }, null, 2));
  process.exit(1);
}
console.log(JSON.stringify({ ok: true, url, status: res.status, csp: csp.slice(0, 180) }));
