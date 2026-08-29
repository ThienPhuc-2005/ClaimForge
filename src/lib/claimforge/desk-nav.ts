/** Primary desk tabs. Arrow keys move between these only — More views are a <select>. */

export const PRIMARY_TAB_IDS = ["findings", "playbook", "forge"] as const;
export type PrimaryTabId = (typeof PRIMARY_TAB_IDS)[number];

export const MORE_TAB_IDS = ["diff", "graph", "loot", "timeline", "traffic", "lab"] as const;
export type MoreTabId = (typeof MORE_TAB_IDS)[number];

export type DeskNavKey = "ArrowRight" | "ArrowLeft" | "Home" | "End";

export function isPrimaryTab(id: string): id is PrimaryTabId {
  return (PRIMARY_TAB_IDS as readonly string[]).includes(id);
}

export function isMoreTab(id: string): id is MoreTabId {
  return (MORE_TAB_IDS as readonly string[]).includes(id);
}

export function isDeskNavKey(key: string): key is DeskNavKey {
  return key === "ArrowRight" || key === "ArrowLeft" || key === "Home" || key === "End";
}

/**
 * Next primary tab for a keyboard event. `focusedId` is the tab-* control that
 * actually has focus (empty when the event is not from a tab button).
 * More-view ids are ignored so arrows never land on inspect views.
 */
export function nextPrimaryTab(focusedId: string, currentTab: string, key: DeskNavKey): PrimaryTabId {
  const last = PRIMARY_TAB_IDS.length - 1;
  const focused = PRIMARY_TAB_IDS.indexOf(focusedId as PrimaryTabId);
  const current = PRIMARY_TAB_IDS.indexOf(currentTab as PrimaryTabId);
  const from = focused >= 0 ? focused : current;
  if (from < 0) {
    return key === "End" ? PRIMARY_TAB_IDS[last]! : PRIMARY_TAB_IDS[0];
  }
  if (key === "Home") return PRIMARY_TAB_IDS[0];
  if (key === "End") return PRIMARY_TAB_IDS[last]!;
  if (key === "ArrowRight") return PRIMARY_TAB_IDS[(from + 1) % PRIMARY_TAB_IDS.length]!;
  return PRIMARY_TAB_IDS[(from - 1 + PRIMARY_TAB_IDS.length) % PRIMARY_TAB_IDS.length]!;
}

/** Only primary tabs have a tab-* node. More views must not produce a dangling labelledby. */
export function deskPanelLabelledBy(tab: string): string | undefined {
  return isPrimaryTab(tab) ? `tab-${tab}` : undefined;
}

export function deskPanelRole(tab: string): "tabpanel" | "region" {
  return isPrimaryTab(tab) ? "tabpanel" : "region";
}
