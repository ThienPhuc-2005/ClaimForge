import { useEffect, useState, type ReactNode } from "react";
import { useForge } from "@/lib/claimforge/store";
import {
  formatRoleHierarchy,
  parseLineList,
  parseRoleHierarchy,
  parseStatusList,
  type AnalysisPolicy,
} from "@/lib/claimforge/policy.ts";

function Field({
  label,
  hint,
  value,
  onChange,
  rows = 3,
}: {
  label: string;
  hint?: string;
  value: string;
  onChange: (v: string) => void;
  rows?: number;
}) {
  return (
    <label className="flex flex-col gap-1 text-xs text-muted">
      {label}
      {hint ? <span className="text-subtle">{hint}</span> : null}
      <textarea
        className="min-h-11 rounded-md border border-border bg-elevated px-2 py-2 font-mono text-sm text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
        rows={rows}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        spellCheck={false}
      />
    </label>
  );
}

function fromPolicy(p: AnalysisPolicy) {
  return {
    version: p.version,
    publicPathPatterns: p.publicPathPatterns.join("\n"),
    sharedPathPatterns: p.sharedPathPatterns.join("\n"),
    privatePathPatterns: p.privatePathPatterns.join("\n"),
    identityPathPatterns: p.identityPathPatterns.join("\n"),
    inventoryFields: p.inventoryFields.join("\n"),
    trustedOwnershipFields: p.trustedOwnershipFields.join("\n"),
    successStatuses: p.successStatuses.join(", "),
    denyStatuses: p.denyStatuses.join(", "),
    requireJwtIss: p.requireJwtIss.join("\n"),
    requireJwtAud: p.requireJwtAud.join("\n"),
    roleHierarchy: formatRoleHierarchy(p.roleHierarchy),
    logoutPathPatterns: p.logoutPathPatterns.join("\n"),
  };
}

function toPolicy(d: ReturnType<typeof fromPolicy>): AnalysisPolicy {
  return {
    version: d.version.trim() || "policy-1",
    publicPathPatterns: parseLineList(d.publicPathPatterns),
    sharedPathPatterns: parseLineList(d.sharedPathPatterns),
    privatePathPatterns: parseLineList(d.privatePathPatterns),
    identityPathPatterns: parseLineList(d.identityPathPatterns),
    inventoryFields: parseLineList(d.inventoryFields),
    trustedOwnershipFields: parseLineList(d.trustedOwnershipFields),
    successStatuses: parseStatusList(d.successStatuses),
    denyStatuses: parseStatusList(d.denyStatuses),
    requireJwtIss: parseLineList(d.requireJwtIss),
    requireJwtAud: parseLineList(d.requireJwtAud),
    roleHierarchy: parseRoleHierarchy(d.roleHierarchy),
    logoutPathPatterns: parseLineList(d.logoutPathPatterns),
  };
}

export function PolicyView() {
  const { policy, applyPolicy, resetPolicy, findingDelta, analyzing, workspace } = useForge();
  const [draft, setDraft] = useState(() => fromPolicy(policy));

  useEffect(() => {
    setDraft(fromPolicy(policy));
  }, [policy]);

  function patch<K extends keyof typeof draft>(key: K, value: (typeof draft)[K]) {
    setDraft((d) => ({ ...d, [key]: value }));
  }

  return (
    <div className="flex flex-col gap-4">
      <p className="text-xs leading-relaxed text-muted">
        Declare how this capture should be scored: public vs private routes, trusted ownership fields, success/deny
        statuses, and role hierarchy. Apply re-runs the engine and lists findings that were added, removed, or changed.
        Request body/query/path still cannot prove ownership.
      </p>
      <div className="flex flex-wrap items-end gap-2">
        <label className="text-xs text-muted">
          Version
          <input
            className="mt-1 h-11 w-40 rounded-md border border-border bg-elevated px-2 font-mono text-sm text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
            value={draft.version}
            onChange={(e) => patch("version", e.target.value)}
            aria-label="Policy version"
          />
        </label>
        <p className="pb-2 font-mono text-xs text-subtle">live {policy.version}</p>
        <button
          type="button"
          className="ml-auto min-h-11 rounded-md bg-accent px-4 text-sm font-medium text-accent-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent disabled:opacity-50"
          disabled={analyzing}
          onClick={() => applyPolicy(toPolicy(draft))}
        >
          {analyzing ? "Re-running…" : "Apply and re-run"}
        </button>
        <button
          type="button"
          className="min-h-11 rounded-md border border-border px-4 text-sm text-fg hover:bg-elevated focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
          onClick={() => resetPolicy()}
        >
          Reset default
        </button>
      </div>

      <div className="grid gap-3 md:grid-cols-2">
        <Field
          label="Public path patterns"
          hint="Regex, one per line. Catalog and docs stay Observation."
          value={draft.publicPathPatterns}
          onChange={(v) => patch("publicPathPatterns", v)}
        />
        <Field
          label="Shared path patterns"
          value={draft.sharedPathPatterns}
          onChange={(v) => patch("sharedPathPatterns", v)}
        />
        <Field
          label="Private path patterns"
          hint="Object routes that can confirm BOLA when ownership is proven."
          value={draft.privatePathPatterns}
          onChange={(v) => patch("privatePathPatterns", v)}
        />
        <Field
          label="Identity path patterns"
          value={draft.identityPathPatterns}
          onChange={(v) => patch("identityPathPatterns", v)}
        />
        <Field
          label="Trusted ownership fields"
          hint="Response JSON keys allowed as owner proof. Extra names like tenantId are allowed."
          value={draft.trustedOwnershipFields}
          onChange={(v) => patch("trustedOwnershipFields", v)}
        />
        <Field
          label="Inventory fields"
          value={draft.inventoryFields}
          onChange={(v) => patch("inventoryFields", v)}
        />
        <Field
          label="Success statuses"
          hint="Comma-separated. Default 200, 201, 202, 204."
          value={draft.successStatuses}
          onChange={(v) => patch("successStatuses", v)}
          rows={2}
        />
        <Field
          label="Deny statuses"
          value={draft.denyStatuses}
          onChange={(v) => patch("denyStatuses", v)}
          rows={2}
        />
        <Field
          label="Required JWT iss"
          hint="Empty = do not require. Verified tokens only."
          value={draft.requireJwtIss}
          onChange={(v) => patch("requireJwtIss", v)}
          rows={2}
        />
        <Field
          label="Required JWT aud"
          value={draft.requireJwtAud}
          onChange={(v) => patch("requireJwtAud", v)}
          rows={2}
        />
        <Field
          label="Logout path patterns"
          value={draft.logoutPathPatterns}
          onChange={(v) => patch("logoutPathPatterns", v)}
          rows={2}
        />
        <Field
          label="Role hierarchy"
          hint="admin: user, viewer — one parent per line."
          value={draft.roleHierarchy}
          onChange={(v) => patch("roleHierarchy", v)}
        />
      </div>

      <section aria-label="Policy re-run changelog" className="rounded-md border border-border bg-elevated p-3">
        <h3 className="text-sm font-medium text-fg">Re-run changelog</h3>
        {!findingDelta.length ? (
          <p className="mt-2 text-xs text-muted">
            {workspace.requests.length
              ? "No finding changes since the last Apply. Edit patterns and Apply to compare."
              : "Load a capture, then Apply to see added / removed / changed findings."}
          </p>
        ) : (
          <ul className="mt-2 flex flex-col gap-1 text-sm">
            {findingDelta.map((row) => (
              <li key={`${row.kind}:${row.fingerprint}`} className="font-mono text-xs text-fg">
                <DeltaKind kind={row.kind} /> {row.title}
                {row.kind === "changed" && row.before && row.after
                  ? ` · ${row.before.confidence}/${row.before.severity} → ${row.after.confidence}/${row.after.severity}`
                  : null}
              </li>
            ))}
          </ul>
        )}
      </section>
    </div>
  );
}

function DeltaKind({ kind }: { kind: "added" | "removed" | "changed" }): ReactNode {
  const cls =
    kind === "added" ? "text-ok" : kind === "removed" ? "text-danger" : "text-warn";
  return <span className={cls}>{kind}</span>;
}
