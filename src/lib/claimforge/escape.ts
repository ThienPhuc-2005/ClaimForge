export function escapeHtml(input: string): string {
  return input
    .replace(/&/g, "\u0026amp;")
    .replace(/</g, "\u0026lt;")
    .replace(/>/g, "\u0026gt;")
    .replace(/"/g, "\u0026quot;")
    .replace(/'/g, "\u0026#39;");
}

/** Neutralize spreadsheet formula injection in exported cells/lists. */
export function neutralizeFormula(input: string): string {
  if (/^[=+\-@\t\r]/.test(input)) return `'${input}`;
  return input;
}

export function safeMdInline(input: string): string {
  return input.replace(/[`|*_[\]<>]/g, " ").replace(/\s+/g, " ").trim();
}
