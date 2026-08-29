import { create } from "zustand";
import { persist } from "zustand/middleware";
import { analyze } from "./analyze.ts";
import { DEMO_A_LABEL, DEMO_B_LABEL, demoActorA, demoActorB } from "./demo.ts";
import type { Workspace } from "./types.ts";

interface ForgeState {
  aLabel: string;
  bLabel: string;
  aRaw: string;
  bRaw: string;
  tab: "findings" | "playbook" | "forge" | "diff" | "graph" | "loot" | "timeline" | "traffic";
  workspace: Workspace;
  setActor: (side: "a" | "b", raw: string) => void;
  setLabel: (side: "a" | "b", label: string) => void;
  setTab: (tab: ForgeState["tab"]) => void;
  loadDemo: () => void;
  clearAll: () => void;
}

function run(aRaw: string, bRaw: string, aLabel: string, bLabel: string): Workspace {
  return analyze(aRaw, bRaw, aLabel, bLabel);
}

const demoA = demoActorA();
const demoB = demoActorB();

export const useForge = create<ForgeState>()(
  persist(
    (set, get) => ({
      aLabel: DEMO_A_LABEL,
      bLabel: DEMO_B_LABEL,
      aRaw: demoA,
      bRaw: demoB,
      tab: "findings",
      workspace: run(demoA, demoB, DEMO_A_LABEL, DEMO_B_LABEL),
      setActor: (side, raw) => {
        const aRaw = side === "a" ? raw : get().aRaw;
        const bRaw = side === "b" ? raw : get().bRaw;
        set({
          aRaw,
          bRaw,
          workspace: run(aRaw, bRaw, get().aLabel, get().bLabel),
        });
      },
      setLabel: (side, label) => {
        const aLabel = side === "a" ? label : get().aLabel;
        const bLabel = side === "b" ? label : get().bLabel;
        set({
          aLabel,
          bLabel,
          workspace: run(get().aRaw, get().bRaw, aLabel, bLabel),
        });
      },
      setTab: (tab) => set({ tab }),
      loadDemo: () => {
        const aRaw = demoActorA();
        const bRaw = demoActorB();
        set({
          aLabel: DEMO_A_LABEL,
          bLabel: DEMO_B_LABEL,
          aRaw,
          bRaw,
          tab: "findings",
          workspace: run(aRaw, bRaw, DEMO_A_LABEL, DEMO_B_LABEL),
        });
      },
      clearAll: () => {
        set({
          aRaw: "",
          bRaw: "",
          workspace: run("", "", get().aLabel, get().bLabel),
        });
      },
    }),
    {
      name: "claimforge-v1",
      partialize: (s) => ({
        aLabel: s.aLabel,
        bLabel: s.bLabel,
        aRaw: s.aRaw,
        bRaw: s.bRaw,
        tab: s.tab,
      }),
      onRehydrateStorage: () => (state) => {
        if (!state) return;
        if ((state.tab as string) === "artifacts") state.tab = "loot";
        state.workspace = run(state.aRaw, state.bRaw, state.aLabel, state.bLabel);
      },
    },
  ),
);
