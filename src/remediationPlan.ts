import { Finding } from "./types";

export type RemediationPlan = {
  sourceReplacement: string;
  envLine: string;
  exampleLine: string;
  willAddEnvToGitignore: boolean;
  conflictReason?: string;
  preview: string;
};

function appendLine(text: string, line: string): string {
  if (text.split(/\r?\n/).some(value => value.trim() === line.trim())) return text;
  return `${text}${text.length && !text.endsWith("\n") ? "\n" : ""}${line}\n`;
}

function hasConflictingValue(envText: string, envVarName: string, expectedLine: string): boolean {
  return envText
    .split(/\r?\n/)
    .some(line => line.startsWith(`${envVarName}=`) && line.trim() !== expectedLine.trim());
}

function hasGitIgnoreEntry(ignoreText: string, entry: string): boolean {
  return ignoreText.split(/\r?\n/).some(line => line.trim() === entry);
}

export function buildRemediationPlan(
  finding: Finding,
  envText: string,
  exampleText: string,
  ignoreText: string
): RemediationPlan {
  const envLine = `${finding.envVarName}=${finding.value}`;
  const exampleLine = `${finding.envVarName}=`;
  const sourceReplacement = `process.env.${finding.envVarName}`;
  const willAddEnvToGitignore = !hasGitIgnoreEntry(ignoreText, ".env");
  const conflictReason = hasConflictingValue(envText, finding.envVarName, envLine)
    ? `Secura found an existing ${finding.envVarName} in .env with a different value.`
    : undefined;

  const preview = [
    `Replace code: ${finding.value.slice(0, 4)}... -> ${sourceReplacement}`,
    `Update .env: ${appendLine(envText, envLine).includes(envLine) ? `ensure ${finding.envVarName} exists` : "no change"}`,
    "Update .env.example: ensure variable placeholder exists",
    `Update .gitignore: ${willAddEnvToGitignore ? "add .env" : "already protected"}`
  ].join("\n");

  return {
    sourceReplacement,
    envLine,
    exampleLine,
    willAddEnvToGitignore,
    conflictReason,
    preview
  };
}

export function applyLine(text: string, line: string): string {
  return appendLine(text, line);
}
