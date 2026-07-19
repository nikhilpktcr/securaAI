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

export type FindingResult = {
  provider: SecretProvider;
  secretType: string;
  severity: SecretSeverity;
  envVarName: string;
  message: string;
  explanation: string;
  filePath: string;
  absolutePath?: string;
  line: number;
  character: number;
  gitStatus?: string;
};

export type ScanStats = {
  open: number;
  scanned: number;
  score: number;
};

export type ScanResult = {
  gitRoot?: string;
  mode?: string;
  commitSha?: string;
  scannedFiles: Array<{ status: string; path: string }>;
  findings: FindingResult[];
  stats: ScanStats;
  scannedAt: string;
};

export type SessionUser = {
  email: string;
  name: string;
};

export type LinkedRepo = {
  input: string;
  localPath?: string;
  owner?: string;
  name?: string;
  source: "local" | "remote" | "github";
  linkedAt: string;
};

export type SessionPayload = {
  user: SessionUser;
  repo: LinkedRepo | null;
  exp?: number;
};
