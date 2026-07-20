export type SecretProvider =
  | "openai"
  | "github"
  | "aws"
  | "stripe"
  | "slack"
  | "google"
  | "anthropic"
  | "generic";

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

export const SECRET_PROVIDERS: SecretProvider[] = [
  "openai",
  "github",
  "aws",
  "stripe",
  "slack",
  "google",
  "anthropic",
  "generic"
];

export function emptyProviderCounts(): Record<SecretProvider, number> {
  return {
    openai: 0,
    github: 0,
    aws: 0,
    stripe: 0,
    slack: 0,
    google: 0,
    anthropic: 0,
    generic: 0
  };
}

/** Source files Secura will scan for free (local + GitHub). */
export function isSupportedScanPath(filePath: string): boolean {
  return /\.(jsx?|tsx?|mjs|cjs|py|go|java|rb|php|rs|cs|kt|swift|scala|env|json|ya?ml|toml|ini|cfg|conf|sh|bash|zsh|ps1|tf|hcl)$/i.test(
    filePath
  );
}

type SecretPattern = {
  provider: SecretProvider;
  secretType: string;
  severity: SecretSeverity;
  envVarName: string;
  regex: RegExp;
  valueGroup: number;
  message: string;
  explanation: string;
};

const PATTERNS: SecretPattern[] = [
  {
    provider: "anthropic",
    secretType: "Anthropic API key",
    severity: "critical",
    envVarName: "ANTHROPIC_API_KEY",
    regex: /(["'`])(sk-ant-[A-Za-z0-9_-]{16,})\1/g,
    valueGroup: 2,
    message: "Secura: Hardcoded Anthropic API key detected.",
    explanation: "Anthropic keys can be abused for model access and unexpected spend."
  },
  {
    provider: "openai",
    secretType: "OpenAI API key",
    severity: "critical",
    envVarName: "OPENAI_API_KEY",
    regex: /(["'`])(sk-(?:proj|svcacct)-[A-Za-z0-9_-]{16,}|sk-(?!ant-)[A-Za-z0-9_-]{20,})\1/g,
    valueGroup: 2,
    message: "Secura: Hardcoded OpenAI API key detected.",
    explanation:
      "OpenAI keys grant direct API usage and can expose data or create billing abuse if committed."
  },
  {
    provider: "github",
    secretType: "GitHub personal access token",
    severity: "critical",
    envVarName: "GITHUB_TOKEN",
    regex:
      /(["'`])((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{20,})\1/g,
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
    provider: "aws",
    secretType: "AWS secret access key",
    severity: "critical",
    envVarName: "AWS_SECRET_ACCESS_KEY",
    regex:
      /\b(?:aws_secret_access_key|secret_access_key)\b\s*[:=]\s*(["'`])([A-Za-z0-9/+=]{40})\1/gi,
    valueGroup: 2,
    message: "Secura: Hardcoded AWS secret access key detected.",
    explanation: "AWS secret keys combined with access key IDs grant cloud control-plane access."
  },
  {
    provider: "stripe",
    secretType: "Stripe API key",
    severity: "critical",
    envVarName: "STRIPE_SECRET_KEY",
    regex: /(["'`])((?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,})\1/g,
    valueGroup: 2,
    message: "Secura: Hardcoded Stripe secret key detected.",
    explanation: "Stripe secret keys can create charges, payouts, and access customer payment data."
  },
  {
    provider: "slack",
    secretType: "Slack token",
    severity: "high",
    envVarName: "SLACK_BOT_TOKEN",
    regex: /(["'`])(xox[baprs]-[A-Za-z0-9-]{10,})\1/g,
    valueGroup: 2,
    message: "Secura: Hardcoded Slack token detected.",
    explanation: "Slack tokens can read channels, post messages, and access workspace data."
  },
  {
    provider: "google",
    secretType: "Google API key",
    severity: "high",
    envVarName: "GOOGLE_API_KEY",
    regex: /(["'`])(AIza[0-9A-Za-z_-]{35})\1/g,
    valueGroup: 2,
    message: "Secura: Hardcoded Google API key detected.",
    explanation: "Google API keys can unlock billed Google Cloud / Maps APIs if unrestricted."
  },
  {
    provider: "generic",
    secretType: "Private key material",
    severity: "critical",
    envVarName: "PRIVATE_KEY",
    regex: /(-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----)/g,
    valueGroup: 1,
    message: "Secura: Private key material detected in source.",
    explanation: "Private keys in repos are a common root-cause of production compromises."
  },
  {
    provider: "generic",
    secretType: "Hardcoded password assignment",
    severity: "medium",
    envVarName: "APP_PASSWORD",
    regex: /\b(?:password|passwd|pwd|secret)\b\s*[:=]\s*(["'`])([^"'`\r\n]{8,})\1/gi,
    valueGroup: 2,
    message: "Secura: Hardcoded password-like assignment detected.",
    explanation:
      "Hardcoded passwords are difficult to rotate and are commonly leaked through source control."
  }
];

function redactValue(value: string): string {
  if (value.startsWith("-----BEGIN")) return "-----BEGIN ***-----";
  if (value.length <= 6) return `${value[0] ?? ""}***`;
  return `${value.slice(0, 4)}...${value.slice(-2)}`;
}

function hasOverlap(start: number, end: number, current: SecretDetection[]): boolean {
  return current.some((item) => start < item.end && end > item.start);
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
