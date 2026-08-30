import type { Finding, FindingConfidence, Severity } from "./types.ts";

const SEV: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const CONF: Record<FindingConfidence, number> = { confirmed: 0, suspicion: 1, observation: 2 };

export function jwtIssueKind(issue: string): string {
  if (/none|unsigned/i.test(issue)) return "alg-none";
  if (/jwk|jku|x5u|kid looks/i.test(issue)) return "key-injection";
  if (/privileged role/i.test(issue)) return "priv-role";
  if (/expired|nbf|lifetime|no exp/i.test(issue)) return "lifetime";
  if (/no iss/i.test(issue)) return "iss";
  if (/no aud/i.test(issue)) return "aud";
  if (/sub and userId/i.test(issue)) return "sub-mismatch";
  return issue.slice(0, 48).toLowerCase();
}

export function mergeFindings(list: Finding[]): Finding[] {
  const map = new Map<string, Finding>();
  for (const f of list) {
    const k = f.fingerprint || `${f.title}|${f.template ?? ""}`;
    const prev = map.get(k);
    if (!prev) {
      map.set(k, { ...f, evidence: [...new Set(f.evidence.filter(Boolean))] });
      continue;
    }
    const pickF =
      SEV[f.severity] < SEV[prev.severity] ||
      (f.severity === prev.severity && CONF[f.confidence] < CONF[prev.confidence]);
    const primary = pickF ? f : prev;
    map.set(k, {
      ...primary,
      severity: SEV[f.severity] < SEV[prev.severity] ? f.severity : prev.severity,
      confidence: CONF[f.confidence] < CONF[prev.confidence] ? f.confidence : prev.confidence,
      evidence: [...new Set([...prev.evidence, ...f.evidence].filter(Boolean))],
      reasonCodes: [...new Set([...prev.reasonCodes, ...f.reasonCodes])],
      reviewState: primary.reviewState,
      missingEvidence: [...new Set([...(prev.missingEvidence ?? []), ...(f.missingEvidence ?? [])])],
      fingerprint: k,
    });
  }
  return [...map.values()].sort((a, b) => SEV[a.severity] - SEV[b.severity] || a.id.localeCompare(b.id));
}
