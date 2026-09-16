import { analyze } from "./analyze.ts";
import { WORKER_ANALYZE_BYTES } from "./limits.ts";
import { DEFAULT_POLICY, type AnalysisPolicy } from "./policy.ts";
import type { Workspace } from "./types.ts";

let worker: Worker | null = null;
let seq = 0;
let yieldGen = 0;
const pending = new Map<number, { resolve: (w: Workspace) => void; reject: (e: Error) => void }>();

export function rejectAllAnalyzeWork(reason: string): void {
  const err = new Error(reason);
  const boxes = [...pending.values()];
  pending.clear();
  const w = worker;
  worker = null;
  if (w) {
    try {
      w.terminate();
    } catch {
      /* already dead */
    }
  }
  for (const box of boxes) box.reject(err);
}

/** Drop in-flight jobs so a newer paste does not wait on stale analyze. */
export function cancelAnalyzeJobs(reason = "analyze cancelled"): void {
  yieldGen += 1;
  rejectAllAnalyzeWork(reason);
}

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
    worker.onerror = (ev) => {
      const msg = ev instanceof ErrorEvent ? ev.message : "analyze worker crashed";
      rejectAllAnalyzeWork(msg || "analyze worker crashed");
    };
    worker.addEventListener("messageerror", () => {
      rejectAllAnalyzeWork("analyze worker message error");
    });
    return worker;
  } catch {
    return null;
  }
}

function analyzeYield(
  aRaw: string,
  bRaw: string,
  aLabel: string,
  bLabel: string,
  policy: AnalysisPolicy,
  specRaw: string,
): Promise<Workspace> {
  const g = ++yieldGen;
  return new Promise((resolve, reject) => {
    setTimeout(() => {
      if (g !== yieldGen) {
        reject(new Error("analyze cancelled"));
        return;
      }
      try {
        resolve(analyze(aRaw, bRaw, aLabel, bLabel, policy, specRaw));
      } catch (e) {
        reject(e instanceof Error ? e : new Error(String(e)));
      }
    }, 0);
  });
}

export function analyzeAsync(
  aRaw: string,
  bRaw: string,
  aLabel: string,
  bLabel: string,
  policy: AnalysisPolicy = DEFAULT_POLICY,
  specRaw = "",
): Promise<Workspace> {
  cancelAnalyzeJobs("analyze superseded");
  const size = aRaw.length + bRaw.length + specRaw.length;
  const w = size >= WORKER_ANALYZE_BYTES ? getWorker() : null;
  if (!w) return analyzeYield(aRaw, bRaw, aLabel, bLabel, policy, specRaw);
  const id = (seq += 1);
  return new Promise((resolve, reject) => {
    pending.set(id, { resolve, reject });
    try {
      w.postMessage({ id, aRaw, bRaw, aLabel, bLabel, policy, specRaw });
    } catch (e) {
      pending.delete(id);
      reject(e instanceof Error ? e : new Error("analyze worker postMessage failed"));
    }
  });
}

export function pendingAnalyzeCount(): number {
  return pending.size;
}
