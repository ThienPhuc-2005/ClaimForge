import type { Workspace } from "./types.ts";
import { redactText, redactWorkspace } from "./redact.ts";

export function engagementMarkdown(ws: Workspace): string {
  const safe = redactWorkspace(ws);
  const lines: string[] = [
    `# ClaimForge engagement`,
    ``,
    `- Actors: **${safe.aLabel} (A)** vs **${safe.bLabel} (B)**`,
    `- Requests: ${safe.requests.length}`,
    `- Findings: ${safe.findings.length} (${safe.findings.filter((f) => f.severity === "critical").length} critical)`,
    `- Generated: ${new Date().toISOString()}`,
    `- Secrets: redacted. Raw HAR/JWT/cookies are not attached.`,
    `- Scope: analysis only — replay curls are for an authorized lab / interceptor, not this app.`,
    ``,
    `## Kill chain`,
    ``,
  ];
  for (const p of safe.paths) {
    lines.push(`### ${p.title}`, ``, p.objective, ``);
    p.steps.forEach((s, i) => lines.push(`${i + 1}. ${s}`));
    lines.push(``);
  }
  lines.push(`## Findings`, ``);
  for (const f of safe.findings) {
    lines.push(`### [${f.severity} · ${f.confidence}] ${f.title}`, ``, redactText(f.why), ``);
    for (const e of f.evidence.filter(Boolean)) lines.push(`- \`${redactText(e)}\``);
    lines.push(``, f.how, ``);
  }
  lines.push(`## Replay pack (lab only, credentials redacted)`, ``);
  for (const r of safe.replays) {
    lines.push(`### ${r.title}`, ``, r.note, ``, "```bash", r.curl, "```", ``);
  }
  lines.push(`## Loot`, ``);
  for (const l of safe.loot) {
    lines.push(`- **${l.label}** (${l.kind}) \`${l.value}\` — ${l.where}`);
  }
  lines.push(``, `## Wordlists`, ``, "```", safe.wordlists.ids.join("\n"), "```", ``);
  return lines.join("\n");
}
