import type * as vscode from "vscode";

export type SecretProvider = "openai" | "github" | "aws" | "generic";
export type SecretSeverity = "critical" | "high" | "medium";

export type SecretDetection = {
  provider: SecretProvider;
  secretType: string;
  severity: SecretSeverity;
  envVarName: string;
  value: string;
  start: number;
  end: number;
  message: string;
  explanation: string;
};

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
