import * as vscode from "vscode";
import { emptyProviderCounts } from "./detectors";
import { AuditEvent, Finding, FindingSnapshot, SecuraStats } from "./types";

const KEY = "secura.stats";
const blank: SecuraStats = {
  found: 0,
  fixed: 0,
  open: 0,
  findingsBySeverity: { critical: 0, high: 0, medium: 0 },
  findingsByProvider: emptyProviderCounts(),
  audit: []
};

export const getStats = (context: vscode.ExtensionContext): SecuraStats =>
  context.workspaceState.get<SecuraStats>(KEY, blank);

const save = (context: vscode.ExtensionContext, value: SecuraStats) => context.workspaceState.update(KEY, value);

function createAudit(event: Omit<AuditEvent, "timestamp">): AuditEvent {
  return { ...event, timestamp: new Date().toISOString() };
}

function withAudit(stats: SecuraStats, event?: Omit<AuditEvent, "timestamp">): SecuraStats {
  if (!event) return stats;
  return { ...stats, audit: [createAudit(event), ...stats.audit].slice(0, 20) };
}

export async function recordScan(context: vscode.ExtensionContext, findings: FindingSnapshot[]): Promise<void> {
  const current = getStats(context);
  const findingsBySeverity: SecuraStats["findingsBySeverity"] = { critical: 0, high: 0, medium: 0 };
  const findingsByProvider: SecuraStats["findingsByProvider"] = emptyProviderCounts();

  for (const finding of findings) {
    findingsBySeverity[finding.severity] += 1;
    findingsByProvider[finding.provider] += 1;
  }

  const open = findings.length;
  const found = Math.max(current.found, current.fixed + open);
  const next = withAudit(
    {
      ...current,
      found,
      open,
      findingsBySeverity,
      findingsByProvider
    },
    open > 0 ? { action: "scan", summary: `${open} open finding${open === 1 ? "" : "s"} currently detected.` } : undefined
  );

  await save(context, next);
}

export async function recordFix(context: vscode.ExtensionContext, finding: Finding): Promise<void> {
  const current = getStats(context);
  const next = withAudit(
    {
      ...current,
      fixed: current.fixed + 1,
      open: Math.max(0, current.open - 1)
    },
    {
      action: "remediation",
      provider: finding.provider,
      severity: finding.severity,
      summary: `Secured ${finding.secretType} in ${finding.document.fileName.split(/[\\/]/).pop() ?? "source file"}.`
    }
  );

  await save(context, next);
}
