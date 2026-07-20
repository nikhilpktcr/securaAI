import type * as vscode from "vscode";
import type { SecretDetection, SecretProvider, SecretSeverity } from "./detectors";

export type { SecretDetection, SecretProvider, SecretSeverity };

export type Finding = SecretDetection & {
  document: vscode.TextDocument;
  range: vscode.Range;
};

export type FindingSnapshot = {
  provider: SecretProvider;
  severity: SecretSeverity;
  secretType: string;
  fileName: string;
  filePath: string;
  line: number;
  character: number;
  message: string;
  explanation: string;
  envVarName: string;
};

export type AuditAction = "scan" | "remediation";
export type AuditEvent = {
  timestamp: string;
  action: AuditAction;
  provider?: SecretProvider;
  severity?: SecretSeverity;
  summary: string;
};

export type SecuraStats = {
  found: number;
  fixed: number;
  open: number;
  findingsBySeverity: Record<SecretSeverity, number>;
  findingsByProvider: Record<SecretProvider, number>;
  audit: AuditEvent[];
};
