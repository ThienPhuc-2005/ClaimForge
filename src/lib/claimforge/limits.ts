/** Captures larger than this are rejected in the UI (HAR + Burp XML). */
export const MAX_CAPTURE_BYTES = 8 * 1024 * 1024;

/** Offload analyze() to a worker above this combined size. */
export const WORKER_ANALYZE_BYTES = 250_000;

export const ANALYZE_DEBOUNCE_MS = 280;
