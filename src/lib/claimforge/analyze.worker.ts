/// <reference lib="webworker" />
import { analyze } from "./analyze.ts";
import { DEFAULT_POLICY, type AnalysisPolicy } from "./policy.ts";

self.onmessage = (ev: MessageEvent) => {
  const data = ev.data as {
    id: number;
    aRaw: string;
    bRaw: string;
    aLabel: string;
    bLabel: string;
    policy?: AnalysisPolicy;
    specRaw?: string;
  };
  try {
    const workspace = analyze(data.aRaw, data.bRaw, data.aLabel, data.bLabel, data.policy ?? DEFAULT_POLICY, data.specRaw ?? "");
    self.postMessage({ id: data.id, ok: true, workspace });
  } catch (e) {
    self.postMessage({ id: data.id, ok: false, error: e instanceof Error ? e.message : String(e) });
  }
};
