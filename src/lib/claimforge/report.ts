import type { Workspace } from "./types.ts";

export function engagementMarkdown(ws: Workspace): string {
  const lines: string[] = [
    `# ClaimForge engagement`,
    ``,
    `- Actors: **${ws.aLabel} (A)** vs **${ws.bLabel} (B)**`,
    `- Requests: ${ws.requests.length}`,
    `- Findings: ${ws.findings.length} (${ws.findings.filter((f) => f.severity === "critical").length} critical)`,
    `- Generated: ${new Date().toISOString()}`,
    `- Scope: analysis only — replay curls are for an authorized lab / interceptor, not this app.`,
    ``,
    `## Kill chain`,
    ``,
  ];
  for (const p of ws.paths) {
    lines.push(`### ${p.title}`, ``, p.objective, ``);
    p.steps.forEach((s, i) => lines.push(`${i + 1}. ${s}`));
    lines.push(``);
  }
  lines.push(`## Findings`, ``);
  for (const f of ws.findings) {
    lines.push(`### [${f.severity}] ${f.title}`, ``, f.why, ``);
    for (const e of f.evidence.filter(Boolean)) lines.push(`- \`${e}\``);
    lines.push(``, f.how, ``);
  }
  lines.push(`## Replay pack (lab only)`, ``);
  for (const r of ws.replays) {
    lines.push(`### ${r.title}`, ``, r.note, ``, "```bash", r.curl, "```", ``);
  }
  lines.push(`## Loot`, ``);
  for (const l of ws.loot) {
    lines.push(`- **${l.label}** (${l.kind}) \`${l.value}\` — ${l.where}`);
  }
  lines.push(``, `## Wordlists`, ``, "```", ws.wordlists.ids.join("\n"), "```", ``);
  return lines.join("\n");
}
