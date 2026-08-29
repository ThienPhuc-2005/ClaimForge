import { analyze } from "./analyze.ts";
import { WORKER_ANALYZE_BYTES } from "./limits.ts";
import type { Workspace } from "./types.ts";

let worker: Worker | null = null;
let seq = 0;
const pending = new Map<number, { resolve: (w: Workspace) => void; reject: (e: Error) => void }>();

function getWorker(): Worker | null {
  if (typeof window === "undefined" || typeof Worker === "undefined") return null;
  if (worker) return worker;
  try {
    worker = new Worker(new URL("./analyze.worker.ts", import.meta.url), { type: "module" });
    worker.onmessage = (ev: MessageEvent) => {
      const data = ev.data as { id: number; ok: boolean; workspace?: Workspace; error?: string };
      const box = pending.get(data.id);
      if (!box) return;
      pending.delete(data.id);
      if (data.ok && data.workspace) box.resolve(data.workspace);
      else box.reject(new Error(data.error ?? "analyze worker failed"));
    };
    worker.onerror = () => {
      worker = null;
    };
    return worker;
  } catch {
    return null;
  }
}

export function analyzeAsync(aRaw: string, bRaw: string, aLabel: string, bLabel: string): Promise<Workspace> {
  const size = aRaw.length + bRaw.length;
  const w = size >= WORKER_ANALYZE_BYTES ? getWorker() : null;
  if (!w) return Promise.resolve(analyze(aRaw, bRaw, aLabel, bLabel));
  const id = (seq += 1);
  return new Promise((resolve, reject) => {
    pending.set(id, { resolve, reject });
    w.postMessage({ id, aRaw, bRaw, aLabel, bLabel });
  });
}
