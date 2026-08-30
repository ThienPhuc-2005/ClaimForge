export function mapCweOwasp(title: string, fingerprint?: string): { cwe: string[]; owasp: string[] } {
  const t = `${title} ${fingerprint ?? ""}`.toLowerCase();
  if (/bola|idor/.test(t)) return { cwe: ["CWE-639"], owasp: ["A01:2021 Broken Access Control"] };
  if (/alg-none|unsigned|jwt/.test(t) && /none|unsigned|jku|jwk|key/.test(t))
    return { cwe: ["CWE-347"], owasp: ["A02:2021 Cryptographic Failures"] };
  if (/cookie/.test(t)) return { cwe: ["CWE-1004"], owasp: ["A05:2021 Security Misconfiguration"] };
  if (/cors/.test(t)) return { cwe: ["CWE-942"], owasp: ["A05:2021 Security Misconfiguration"] };
  if (/mass-assign/.test(t)) return { cwe: ["CWE-915"], owasp: ["A08:2021 Software and Data Integrity Failures"] };
  if (/token in query/.test(t)) return { cwe: ["CWE-598"], owasp: ["A02:2021 Cryptographic Failures"] };
  if (/logout|session/.test(t)) return { cwe: ["CWE-613"], owasp: ["A07:2021 Identification and Authentication Failures"] };
  return { cwe: [], owasp: [] };
}

export function cvssDraft(severity: string): { score: number | null; vector: string | null; status: "draft" } {
  const score =
    severity === "critical" ? 9.1 : severity === "high" ? 7.5 : severity === "medium" ? 5.3 : severity === "low" ? 3.1 : 0;
  return {
    score,
    vector: score ? `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:${score >= 7 ? "H" : "L"}/I:L/A:N` : null,
    status: "draft",
  };
}
