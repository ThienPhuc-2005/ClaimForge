import { create } from "zustand";
import { persist } from "zustand/middleware";
import { analyze } from "./analyze.ts";
import { analyzeAsync, cancelAnalyzeJobs } from "./analyze-async.ts";
import { ANALYZE_DEBOUNCE_MS, MAX_CAPTURE_BYTES } from "./limits.ts";
import { DEMO_A_LABEL, DEMO_B_LABEL, demoActorA, demoActorB } from "./demo.ts";
import type { ReviewState, Workspace } from "./types.ts";
import { applyReviewOverrides, applyReviewTransition } from "./review.ts";
import {
  applyPolicyEdit,
  clonePolicy,
  DEFAULT_POLICY,
  diffFindingSets,
  policyApplyDecision,
  type AnalysisPolicy,
  type PolicyPatternError,
  type PolicyRerunChange,
} from "./policy.ts";

export type DeskTab =
  | "findings"
  | "playbook"
  | "forge"
  | "diff"
  | "graph"
  | "loot"
  | "timeline"
  | "traffic"
  | "lab"
  | "policy";

interface ForgeState {
  aLabel: string;
  bLabel: string;
  aRaw: string;
  bRaw: string;
  persistCaptures: boolean;
  analyzing: boolean;
  importError: string | null;
  parseErrorA: string | null;
  parseErrorB: string | null;
  tab: DeskTab;
  workspace: Workspace;
  reviewByFingerprint: Record<string, ReviewState>;
  policy: AnalysisPolicy;
  findingDelta: PolicyRerunChange[];
  policyErrors: PolicyPatternError[];
  setActor: (side: "a" | "b", raw: string, immediate?: boolean) => void;
  setLabel: (side: "a" | "b", label: string) => void;
  setTab: (tab: ForgeState["tab"]) => void;
  setPersistCaptures: (v: boolean) => void;
  setImportError: (msg: string | null) => void;
  setFindingReview: (fingerprint: string, to: ReviewState) => boolean;
  applyPolicy: (draft: AnalysisPolicy) => boolean;
  resetPolicy: () => void;
  loadDemo: () => void;
  clearAll: () => void;
}

function emptyWs(aLabel: string, bLabel: string, policy: AnalysisPolicy = DEFAULT_POLICY): Workspace {
  return analyze("", "", aLabel, bLabel, policy);
}

function parseFields(ws: Workspace) {
  return {
    parseErrorA: ws.parseErrorA ?? null,
    parseErrorB: ws.parseErrorB ?? null,
  };
}

let debounceTimer: ReturnType<typeof setTimeout> | undefined;
let runGen = 0;

function runAnalyze(
  aRaw: string,
  bRaw: string,
  aLabel: string,
  bLabel: string,
  policy: AnalysisPolicy,
  set: (p: Partial<ForgeState>) => void,
  prevFindings?: Workspace["findings"],
) {
  const gen = (runGen += 1);
  set({ analyzing: true, importError: null });
  void analyzeAsync(aRaw, bRaw, aLabel, bLabel, policy)
    .then((workspace) => {
      if (gen !== runGen) return;
      const overlays = useForge.getState().reviewByFingerprint;
      const findings = applyReviewOverrides(workspace.findings, overlays);
      set({
        workspace: { ...workspace, findings },
        analyzing: false,
        findingDelta: prevFindings ? diffFindingSets(prevFindings, findings) : [],
        ...parseFields(workspace),
      });
    })
    .catch((e) => {
      if (gen !== runGen) return;
      const msg = e instanceof Error ? e.message : "analyze failed";
      if (/superseded|cancelled/i.test(msg)) return;
      set({ analyzing: false, importError: msg });
    });
}

export const useForge = create<ForgeState>()(
  persist(
    (set, get) => ({
      aLabel: DEMO_A_LABEL,
      bLabel: DEMO_B_LABEL,
      aRaw: "",
      bRaw: "",
      persistCaptures: false,
      analyzing: false,
      importError: null,
      parseErrorA: null,
      parseErrorB: null,
      tab: "findings",
      workspace: emptyWs(DEMO_A_LABEL, DEMO_B_LABEL),
      reviewByFingerprint: {},
      policy: clonePolicy(DEFAULT_POLICY),
      findingDelta: [],
      policyErrors: [],
      setActor: (side, raw, immediate) => {
        if (raw.length > MAX_CAPTURE_BYTES) {
          set({ importError: `Capture exceeds ${Math.round(MAX_CAPTURE_BYTES / (1024 * 1024))} MB limit.` });
          return;
        }
        const aRaw = side === "a" ? raw : get().aRaw;
        const bRaw = side === "b" ? raw : get().bRaw;
        set({ aRaw, bRaw, importError: null, findingDelta: [] });
        const kick = () => runAnalyze(aRaw, bRaw, get().aLabel, get().bLabel, get().policy, set);
        if (immediate) {
          if (debounceTimer) clearTimeout(debounceTimer);
          kick();
          return;
        }
        if (debounceTimer) clearTimeout(debounceTimer);
        debounceTimer = setTimeout(kick, ANALYZE_DEBOUNCE_MS);
      },
      setLabel: (side, label) => {
        const aLabel = side === "a" ? label : get().aLabel;
        const bLabel = side === "b" ? label : get().bLabel;
        set({ aLabel, bLabel, findingDelta: [] });
        runAnalyze(get().aRaw, get().bRaw, aLabel, bLabel, get().policy, set);
      },
      setTab: (tab) => set({ tab }),
      setPersistCaptures: (persistCaptures) => set({ persistCaptures }),
      setImportError: (importError) => set({ importError }),
      setFindingReview: (fingerprint, to) => {
        const ws = get().workspace;
        const finding = ws.findings.find((f) => (f.fingerprint || f.id) === fingerprint);
        if (!finding) return false;
        try {
          applyReviewTransition(finding.reviewState, to);
        } catch {
          return false;
        }
        const reviewByFingerprint = { ...get().reviewByFingerprint, [fingerprint]: to };
        set({
          reviewByFingerprint,
          workspace: {
            ...ws,
            findings: ws.findings.map((f) =>
              (f.fingerprint || f.id) === fingerprint ? { ...f, reviewState: to } : f,
            ),
          },
        });
        return true;
      },
      applyPolicy: (draft) => {
        const decision = policyApplyDecision(draft);
        if (!decision.apply) {
          set({ policyErrors: decision.errors });
          return false;
        }
        const policy = applyPolicyEdit(get().policy, draft);
        const prevFindings = get().workspace.findings;
        set({ policy, policyErrors: [] });
        runAnalyze(get().aRaw, get().bRaw, get().aLabel, get().bLabel, policy, set, prevFindings);
        return true;
      },
      resetPolicy: () => {
        const policy = clonePolicy(DEFAULT_POLICY);
        const prevFindings = get().workspace.findings;
        set({ policy, policyErrors: [] });
        runAnalyze(get().aRaw, get().bRaw, get().aLabel, get().bLabel, policy, set, prevFindings);
      },
      loadDemo: () => {
        const aRaw = demoActorA();
        const bRaw = demoActorB();
        set({
          aLabel: DEMO_A_LABEL,
          bLabel: DEMO_B_LABEL,
          aRaw,
          bRaw,
          tab: "findings",
          importError: null,
          findingDelta: [],
        });
        runAnalyze(aRaw, bRaw, DEMO_A_LABEL, DEMO_B_LABEL, get().policy, set);
      },
      clearAll: () => {
        cancelAnalyzeJobs("cleared");
        runGen += 1;
        set({
          aRaw: "",
          bRaw: "",
          importError: null,
          parseErrorA: null,
          parseErrorB: null,
          analyzing: false,
          reviewByFingerprint: {},
          findingDelta: [],
          workspace: emptyWs(get().aLabel, get().bLabel, get().policy),
        });
      },
    }),
    {
      name: "claimforge-v2",
      partialize: (s) =>
        s.persistCaptures
          ? {
              aLabel: s.aLabel,
              bLabel: s.bLabel,
              aRaw: s.aRaw,
              bRaw: s.bRaw,
              tab: s.tab,
              persistCaptures: true as const,
              reviewByFingerprint: s.reviewByFingerprint,
              policy: s.policy,
            }
          : {
              aLabel: s.aLabel,
              bLabel: s.bLabel,
              tab: s.tab,
              persistCaptures: false as const,
              reviewByFingerprint: s.reviewByFingerprint,
              policy: s.policy,
            },
      onRehydrateStorage: () => (state) => {
        if (typeof localStorage !== "undefined") {
          try {
            localStorage.removeItem("claimforge");
            localStorage.removeItem("claimforge-v1");
          } catch {
            /* private mode */
          }
        }
        if (!state) return;
        if (!state.reviewByFingerprint) state.reviewByFingerprint = {};
        if (!state.policy) state.policy = clonePolicy(DEFAULT_POLICY);
        if (!state.policy.jwksHostnameAllowlist) state.policy.jwksHostnameAllowlist = [];
        if (state.policy.jwksTeamMode == null) state.policy.jwksTeamMode = false;
        if (!state.findingDelta) state.findingDelta = [];
        if (!state.policyErrors) state.policyErrors = [];
        if ((state.tab as string) === "artifacts") state.tab = "findings";
        const busy = state.analyzing || state.workspace.requests.length > 0;
        if (!state.persistCaptures && !busy) {
          state.aRaw = "";
          state.bRaw = "";
        }
        if (!busy) state.workspace = emptyWs(state.aLabel, state.bLabel, state.policy);
        if ((state.aRaw || state.bRaw) && !state.analyzing) {
          queueMicrotask(() => {
            runAnalyze(state.aRaw, state.bRaw, state.aLabel, state.bLabel, state.policy, (p) =>
              useForge.setState(p),
            );
          });
        }
      },
    },
  ),
);
