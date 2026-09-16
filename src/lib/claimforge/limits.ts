/** Captures larger than this are rejected in the UI (HAR + Burp XML). */
export const MAX_CAPTURE_BYTES = 24 * 1024 * 1024;

/** Offload analyze() to a worker above this combined size. */
export const WORKER_ANALYZE_BYTES = 24_000;

export const ANALYZE_DEBOUNCE_MS = 280;

/** Cap stored requests per actor so AuthZ pairing stays linear in RAM.
 *  Dropped requests are surfaced via Workspace.truncation, never silently. */
export const MAX_REQUESTS_PER_ACTOR = 4_000;

/** Truncate bodies kept on each request after parse. */
export const MAX_BODY_CHARS = 24_000;

/** Max A/B same-path 2xx pairs scored per template. */
export const MAX_SAME_OBJECT_PAIRS = 48;
