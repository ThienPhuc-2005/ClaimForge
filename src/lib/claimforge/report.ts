import { escapeHtml, neutralizeFormula, safeMdInline } from "./escape.ts";
import { toReportDTO, type ReportDTO } from "./report-dto.ts";
import type { Workspace } from "./types.ts";

export { toReportDTO, REPORT_SCHEMA_VERSION } from "./report-dto.ts";
export type { ReportDTO, ReportFindingDTO } from "./report-dto.ts";

/** Exporters accept only ReportDTO. Workspace helpers redact then map. */
export function buildReport(ws: Workspace): ReportDTO {
  return toReportDTO(ws);
}

export function exportReportJson(ws: Workspace): ReportDTO {
  return buildReport(ws);
}

export function renderReportJson(dto: ReportDTO): string {
  return JSON.stringify(dto, null, 2);
}

export function renderReportMarkdown(dto: ReportDTO): string {
  const lines: string[] = [
    `# ClaimForge engagement`,
    ``,
    `- Actors: **${safeMdInline(dto.actors.A)} (A)** vs **${safeMdInline(dto.actors.B)} (B)**`,
    `- Schema: ${dto.schemaVersion} · engine ${dto.engineVersion} · policy ${dto.policyVersion}`,
    `- Findings: ${dto.findings.length} (${dto.findings.filter((f) => f.severity === "critical").length} critical)`,
    `- Generated: ${dto.generated}`,
    `- Secrets: redacted. Raw HAR/JWT/cookies are not attached.`,
    `- Redaction preview: ${dto.redaction.preview.join("; ")}`,
    `- Confidence is a capture heuristic. Confirmed is not a ship-it verdict. CVSS is draft until analyst review.`,
    ``,
    `## Kill chain`,
    ``,
  ];
  for (const p of dto.paths) {
    lines.push(`### ${safeMdInline(p.title)}`, ``, safeMdInline(p.objective), ``);
    p.steps.forEach((s, i) => lines.push(`${i + 1}. ${safeMdInline(s)}`));
    lines.push(``);
  }
  lines.push(`## Findings`, ``);
  for (const f of dto.findings) {
    lines.push(`### [${f.severity} · ${f.confidence} · ${f.reviewState}] ${safeMdInline(f.title)}`, ``, safeMdInline(f.why), ``);
    if (f.reasonCodes.length) lines.push(`- Reason: ${f.reasonCodes.map(safeMdInline).join(", ")}`);
    if (f.cwe.length) lines.push(`- CWE: ${f.cwe.join(", ")}`);
    if (f.owasp.length) lines.push(`- OWASP: ${f.owasp.join(", ")}`);
    if (f.cvssDraft.score != null) lines.push(`- CVSS draft: ${f.cvssDraft.score} (${f.cvssDraft.status})`);
    for (const e of f.evidence.filter(Boolean)) lines.push(`- \`${safeMdInline(e)}\``);
    lines.push(``, safeMdInline(f.how), ``);
  }
  lines.push(`## Replay pack (lab only, credentials redacted)`, ``);
  for (const r of dto.replays) {
    lines.push(`### ${safeMdInline(r.title)}`, ``, safeMdInline(r.note), ``, "```bash", r.curl, "```", ``);
  }
  lines.push(`## Loot`, ``);
  for (const l of dto.loot) {
    lines.push(`- **${safeMdInline(l.label)}** (${l.kind}) \`${safeMdInline(l.value)}\` — ${safeMdInline(l.where)}`);
  }
  lines.push(``, `## Wordlists`, ``, "```", dto.wordlists.ids.map(neutralizeFormula).join("\n"), "```", ``);
  return lines.join("\n");
}

export function engagementMarkdown(ws: Workspace): string {
  return renderReportMarkdown(buildReport(ws));
}

export function renderReportHtml(dto: ReportDTO): string {
  const findings = dto.findings
    .map(
      (f) => `<article>
<h3>${escapeHtml(`[${f.severity} · ${f.confidence} · ${f.reviewState}] ${f.title}`)}</h3>
<p>${escapeHtml(f.why)}</p>
<p>${escapeHtml((f.reasonCodes ?? []).join(", "))}</p>
<ul>${f.cwe.map((c) => `<li>${escapeHtml(c)}</li>`).join("")}</ul>
<pre>${escapeHtml(f.evidence.join("\n"))}</pre>
<p>${escapeHtml(f.how)}</p>
</article>`,
    )
    .join("\n");
  return `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"/><title>ClaimForge report</title></head>
<body>
<h1>ClaimForge engagement</h1>
<p>${escapeHtml(dto.actors.A)} vs ${escapeHtml(dto.actors.B)}</p>
<p>${escapeHtml(dto.redaction.preview.join("; "))}</p>
${findings}
</body></html>
`;
}

export function exportReportHtml(ws: Workspace): string {
  return renderReportHtml(buildReport(ws));
}

function pdfEscape(s: string): string {
  return s.replace(/\\/g, "\\\\").replace(/\(/g, "\\(").replace(/\)/g, "\\)");
}

/** Minimal PDF 1.4 text dump — no native deps. */
export function renderReportPdf(dto: ReportDTO): Uint8Array {
  const lines = [
    "ClaimForge report (redacted)",
    `${dto.actors.A} vs ${dto.actors.B}`,
    ...dto.redaction.preview,
    ...dto.findings.map((f) => `[${f.severity}] ${f.title}`),
  ].flatMap((l) => {
    const s = l.slice(0, 90);
    return [s];
  });
  const content = lines
    .map((l, i) => `BT /F1 10 Tf 48 ${760 - i * 14} Td (${pdfEscape(l)}) Tj ET`)
    .join("\n");
  const objects: string[] = [];
  objects.push("1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj");
  objects.push("2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj");
  objects.push(
    "3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >> endobj",
  );
  objects.push(`4 0 obj << /Length ${content.length} >> stream\n${content}\nendstream endobj`);
  objects.push("5 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> endobj");
  let body = "%PDF-1.4\n";
  const offsets = [0];
  for (const obj of objects) {
    offsets.push(body.length);
    body += obj + "\n";
  }
  const xrefPos = body.length;
  body += `xref\n0 ${objects.length + 1}\n`;
  body += "0000000000 65535 f \n";
  for (let i = 1; i <= objects.length; i++) {
    body += `${String(offsets[i]).padStart(10, "0")} 00000 n \n`;
  }
  body += `trailer << /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${xrefPos}\n%%EOF`;
  return new TextEncoder().encode(body);
}

export function exportReportPdf(ws: Workspace): Uint8Array {
  return renderReportPdf(buildReport(ws));
}
