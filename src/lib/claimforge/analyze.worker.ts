/// <reference lib="webworker" />
import { analyze } from "./analyze.ts";

self.onmessage = (ev: MessageEvent) => {
  const data = ev.data as { id: number; aRaw: string; bRaw: string; aLabel: string; bLabel: string };
  try {
    const workspace = analyze(data.aRaw, data.bRaw, data.aLabel, data.bLabel);
    self.postMessage({ id: data.id, ok: true, workspace });
  } catch (e) {
    self.postMessage({ id: data.id, ok: false, error: e instanceof Error ? e.message : String(e) });
  }
};
