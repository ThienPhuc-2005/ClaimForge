import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { P1_GATES, P1_ITEMS } from "./p1-gates.ts";

const here = dirname(fileURLToPath(import.meta.url));

function testTitles(src: string): Set<string> {
  const titles = new Set<string>();
  const re = /\btest\(\s*(?:`([^`]+)`|"([^"]+)"|'([^']+)')/g;
  let match: RegExpExecArray | null;
  while ((match = re.exec(src))) {
    const title = match[1] ?? match[2] ?? match[3];
    if (title) titles.add(title);
  }
  return titles;
}

test("P1 catalog covers unique ids and every P1 item", () => {
  const ids = P1_GATES.map((g) => g.id);
  assert.equal(ids.length, new Set(ids).size);
  for (const item of P1_ITEMS) {
    assert.ok(P1_GATES.some((g) => g.p1 === item), `missing gate for ${item}`);
  }
});

test("P1 every gate points at a test title that exists", () => {
  const cache = new Map<string, Set<string>>();
  for (const g of P1_GATES) {
    const [file, ...rest] = g.evidenceTest.split(":");
    const title = rest.join(":");
    assert.ok(file && title, `${g.id} missing file:title`);
    const path = join(here, file);
    assert.ok(existsSync(path), `${g.id} missing ${file}`);
    if (!cache.has(file)) cache.set(file, testTitles(readFileSync(path, "utf8")));
    assert.ok(cache.get(file)!.has(title), `${g.id} missing test title ${JSON.stringify(title)}`);
    assert.ok(g.before.length > 8 && g.after.length > 8, g.id);
  }
});
