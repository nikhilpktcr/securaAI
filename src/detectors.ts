import { SecretDetection } from "./types";

type SecretPattern = {
  provider: SecretDetection["provider"];
  secretType: string;
  severity: SecretDetection["severity"];
  envVarName: string;
  regex: RegExp;
  valueGroup: number;
  message: string;
  explanation: string;
};

const PATTERNS: SecretPattern[] = [
  {
    provider: "openai",
    secretType: "OpenAI API key",
    severity: "critical",
    envVarName: "OPENAI_API_KEY",
    regex: /(["'`])(sk-[A-Za-z0-9_-]{12,})\1/g,
    valueGroup: 2,
    message: "Secura: Hardcoded OpenAI API key detected.",
    explanation: "OpenAI keys grant direct API usage and can expose data or create billing abuse if committed."
  },
  {
    provider: "github",
    secretType: "GitHub personal access token",
    severity: "critical",
    envVarName: "GITHUB_TOKEN",
    regex: /(["'`])((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{20,})\1/g,
    valueGroup: 2,
    message: "Secura: Hardcoded GitHub token detected.",
    explanation: "GitHub tokens can expose repositories, workflows, and organization resources."
  },
  {
    provider: "aws",
    secretType: "AWS access key ID",
    severity: "high",
    envVarName: "AWS_ACCESS_KEY_ID",
    regex: /(["'`])((?:AKIA|ASIA)[0-9A-Z]{16})\1/g,
    valueGroup: 2,
    message: "Secura: Hardcoded AWS access key ID detected.",
    explanation: "AWS credentials in source can enable unauthorized cloud resource access."
  },
  {
    provider: "generic",
    secretType: "Hardcoded password assignment",
    severity: "medium",
    envVarName: "APP_PASSWORD",
    regex: /\b(?:password|passwd|pwd|secret)\b\s*[:=]\s*(["'`])([^"'`\r\n]{8,})\1/gi,
    valueGroup: 2,
    message: "Secura: Hardcoded password-like assignment detected.",
    explanation: "Hardcoded passwords are difficult to rotate and are commonly leaked through source control."
  }
];

function redactValue(value: string): string {
  if (value.length <= 6) return `${value[0] ?? ""}***`;
  return `${value.slice(0, 4)}...${value.slice(-2)}`;
}

function hasOverlap(start: number, end: number, current: SecretDetection[]): boolean {
  return current.some(item => start < item.end && end > item.start);
}

export function detectSecrets(text: string): SecretDetection[] {
  const findings: SecretDetection[] = [];

  for (const pattern of PATTERNS) {
    for (const match of text.matchAll(pattern.regex)) {
      const rawValue = match[pattern.valueGroup];
      if (!rawValue) continue;
      const valueIndex = match[0].indexOf(rawValue);
      const start = (match.index ?? 0) + Math.max(valueIndex, 0);
      const end = start + rawValue.length;
      if (hasOverlap(start, end, findings)) continue;

      findings.push({
        provider: pattern.provider,
        secretType: pattern.secretType,
        severity: pattern.severity,
        envVarName: pattern.envVarName,
        value: rawValue,
        start,
        end,
        message: `${pattern.message} Use process.env.${pattern.envVarName} before commit.`,
        explanation: `${pattern.explanation} Detected value: ${redactValue(rawValue)}`
      });
    }
  }

  return findings.sort((a, b) => a.start - b.start);
}
