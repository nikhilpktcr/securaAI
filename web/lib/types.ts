export type {
  SecretDetection,
  SecretProvider,
  SecretSeverity
} from "./detectors";

export type FindingResult = {
  provider: import("./detectors").SecretProvider;
  secretType: string;
  severity: import("./detectors").SecretSeverity;
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
