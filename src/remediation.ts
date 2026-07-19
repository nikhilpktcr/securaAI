import * as vscode from "vscode";
import { applyLine, buildRemediationPlan } from "./remediationPlan";
import { Finding } from "./types";

async function readText(uri: vscode.Uri): Promise<string> {
  try {
    return Buffer.from(await vscode.workspace.fs.readFile(uri)).toString("utf8");
  } catch {
    return "";
  }
}

export async function applySecretFix(finding: Finding): Promise<boolean> {
  const root = vscode.workspace.getWorkspaceFolder(finding.document.uri);
  if (!root) {
    vscode.window.showErrorMessage("Secura needs an open workspace to safely create .env files.");
    return false;
  }

  const env = vscode.Uri.joinPath(root.uri, ".env");
  const example = vscode.Uri.joinPath(root.uri, ".env.example");
  const ignore = vscode.Uri.joinPath(root.uri, ".gitignore");
  const [envText, exampleText, ignoreText] = await Promise.all([readText(env), readText(example), readText(ignore)]);

  const plan = buildRemediationPlan(finding, envText, exampleText, ignoreText);
  if (plan.conflictReason) {
    vscode.window.showErrorMessage(plan.conflictReason);
    return false;
  }

  const choice = await vscode.window.showWarningMessage(
    `Secura will apply this fix:\n\n${plan.preview}`,
    { modal: true },
    "Apply secure fix"
  );
  if (choice !== "Apply secure fix") return false;

  const edit = new vscode.WorkspaceEdit();
  edit.replace(finding.document.uri, finding.range, plan.sourceReplacement);
  edit.createFile(env, { ignoreIfExists: true });
  edit.createFile(example, { ignoreIfExists: true });
  edit.createFile(ignore, { ignoreIfExists: true });
  edit.replace(env, new vscode.Range(0, 0, 0, 0), applyLine(envText, plan.envLine));
  edit.replace(example, new vscode.Range(0, 0, 0, 0), applyLine(exampleText, plan.exampleLine));
  if (plan.willAddEnvToGitignore) {
    edit.replace(ignore, new vscode.Range(0, 0, 0, 0), applyLine(ignoreText, ".env"));
  }

  return vscode.workspace.applyEdit(edit);
}
