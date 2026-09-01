import assert from "node:assert/strict";
import { test } from "node:test";
import {
  deskPanelLabelledBy,
  deskPanelRole,
  isDeskNavKey,
  isMoreTab,
  isPrimaryTab,
  MORE_TAB_IDS,
  nextPrimaryTab,
  PRIMARY_TAB_IDS,
} from "./desk-nav.ts";

test("arrow keys cycle only the three primary tabs", () => {
  assert.equal(nextPrimaryTab("findings", "findings", "ArrowRight"), "playbook");
  assert.equal(nextPrimaryTab("playbook", "playbook", "ArrowRight"), "forge");
  assert.equal(nextPrimaryTab("forge", "forge", "ArrowRight"), "findings");
  assert.equal(nextPrimaryTab("findings", "findings", "ArrowLeft"), "forge");
});

test("Home and End jump to first/last primary tab", () => {
  assert.equal(nextPrimaryTab("playbook", "playbook", "Home"), "findings");
  assert.equal(nextPrimaryTab("playbook", "playbook", "End"), "forge");
});

test("arrows ignore More-view ids and enter at Findings", () => {
  assert.equal(nextPrimaryTab("diff", "diff", "ArrowRight"), "findings");
  assert.equal(nextPrimaryTab("", "lab", "ArrowLeft"), "findings");
  assert.equal(nextPrimaryTab("", "team", "ArrowRight"), "findings");
  assert.equal(nextPrimaryTab("", "graph", "End"), "forge");
  for (const key of ["ArrowRight", "ArrowLeft", "Home", "End"] as const) {
    assert.equal(isPrimaryTab(nextPrimaryTab("graph", "loot", key)), true);
    assert.equal(isMoreTab(nextPrimaryTab("graph", "loot", key)), false);
  }
});

test("labelledby only points at real tab-* ids", () => {
  for (const id of PRIMARY_TAB_IDS) {
    assert.equal(deskPanelLabelledBy(id), `tab-${id}`);
    assert.equal(deskPanelRole(id), "tabpanel");
  }
  for (const id of MORE_TAB_IDS) {
    assert.equal(deskPanelLabelledBy(id), undefined);
    assert.equal(deskPanelRole(id), "region");
  }
  assert.equal(deskPanelLabelledBy("artifacts"), undefined);
});

test("desk nav key guard", () => {
  assert.equal(isDeskNavKey("ArrowRight"), true);
  assert.equal(isDeskNavKey("Tab"), false);
  assert.equal(isDeskNavKey("Enter"), false);
});
