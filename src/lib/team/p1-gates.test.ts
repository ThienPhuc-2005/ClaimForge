import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { P1_GATES, P1_ITEMS } from "./p1-gates.ts";

const here = dirname(fileURLToPath(import.meta.url));

test("P1.1 catalog covers unique ids and every P1.1 item", () => {
  const ids = P1_GATES.map((g) => g.id);
  assert.equal(ids.length, new Set(ids).size);
  for (const item of P1_ITEMS) {
    assert.ok(P1_GATES.some((g) => g.p1 === item), `missing gate for ${item}`);
  }
});

test("P1.1 every gate points at a test file that exists", () => {
  for (const g of P1_GATES) {
    const file = g.evidenceTest.split(":")[0]!;
    assert.ok(existsSync(join(here, file)), `${g.id} missing ${file}`);
    assert.ok(g.before.length > 8 && g.after.length > 8, g.id);
  }
});
