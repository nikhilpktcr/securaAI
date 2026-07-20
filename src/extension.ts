import * as vscode from "vscode";
import { execFile } from "node:child_process";
import * as path from "node:path";
import { promisify } from "node:util";
import { openDashboard } from "./dashboard";
import { applySecretFix } from "./remediation";
import { isSupportedScanPath } from "./detectors";
import { scanDocument } from "./scanner";
import { getStats, recordFix, recordScan } from "./stats";
import { Finding, FindingSnapshot } from "./types";

const execFileAsync = promisify(execFile);

function fileNameOf(document: vscode.TextDocument): string {
  return document.fileName.split(/[\\/]/).pop() ?? "source file";
}

function flattenSnapshots(findings: Map<string, Finding[]>): FindingSnapshot[] {
  return [...findings.values()].flatMap(list =>
    list.map(item => ({
      provider: item.provider,
      severity: item.severity,
      secretType: item.secretType,
      fileName: fileNameOf(item.document),
      filePath: item.document.uri.fsPath,
      line: item.range.start.line + 1,
      character: item.range.start.character + 1,
      message: item.message,
      explanation: item.explanation,
      envVarName: item.envVarName
    }))
  );
}

async function persistFindingsForTriage(findings: Map<string, Finding[]>): Promise<void> {
  const folder = vscode.workspace.workspaceFolders?.[0];
  if (!folder) return;

  const details = flattenSnapshots(findings);
  const payload = {
    updatedAt: new Date().toISOString(),
    open: details.length,
    findings: details
  };

  const outPath = vscode.Uri.joinPath(folder.uri, "demo", "latest-findings.json");
  await vscode.workspace.fs.writeFile(outPath, Buffer.from(JSON.stringify(payload, null, 2), "utf8"));
}

function diagnosticSeverity(finding: Finding): vscode.DiagnosticSeverity {
  if (finding.severity === "critical") return vscode.DiagnosticSeverity.Error;
  if (finding.severity === "high") return vscode.DiagnosticSeverity.Warning;
  return vscode.DiagnosticSeverity.Information;
}

function findingForRange(list: Finding[], range: vscode.Range): Finding | undefined {
  return list.find(item => item.range.intersection(range));
}

function activeFinding(findings: Map<string, Finding[]>): Finding | undefined {
  const editor = vscode.window.activeTextEditor;
  if (!editor) return undefined;
  const list = findings.get(editor.document.uri.toString()) ?? [];
  return findingForRange(list, editor.selection) ?? list[0];
}

function isSupportedPath(filePath: string): boolean {
  return isSupportedScanPath(filePath);
}

function parsePorcelainZ(stdout: string): string[] {
  const entries = stdout.split("\0").filter(Boolean);
  const paths: string[] = [];
  for (let index = 0; index < entries.length; index += 1) {
    const entry = entries[index];
    if (entry.length < 4) continue;
    const status = entry.slice(0, 2);
    let filePath = entry.slice(3);

    // In -z mode, rename/copy entries are "old\0new\0"; use the destination path.
    if (status.includes("R") || status.includes("C")) {
      const destination = entries[index + 1];
      if (destination) {
        filePath = destination;
        index += 1;
      }
    }

    const normalized = filePath.replace(/\\/g, "/").trim();
    if (normalized && isSupportedPath(normalized)) {
      paths.push(normalized);
    }
  }
  return paths;
}

async function getGitRoot(startPath: string): Promise<string> {
  const { stdout } = await execFileAsync("git", ["rev-parse", "--show-toplevel"], { cwd: startPath });
  return stdout.trim();
}

async function getGitModifiedFiles(startPath: string): Promise<{ gitRoot: string; files: string[] }> {
  const gitRoot = await getGitRoot(startPath);
  const { stdout } = await execFileAsync("git", ["status", "--porcelain", "-z", "--untracked-files=all"], {
    cwd: gitRoot
  });
  return { gitRoot, files: parsePorcelainZ(stdout) };
}

function updateScanStatus(
  item: vscode.StatusBarItem,
  mode: "idle" | "manual" | "autosave",
  scannedFiles = 0,
  findings = 0
): void {
  if (mode === "idle") {
    item.text = "$(shield) Secura ready";
    item.tooltip = "Secura is ready. Run 'Secura: Scan modified files for security issues' to validate git-modified files.";
    return;
  }

  const modeLabel = mode === "manual" ? "Manual scan" : "Auto-save scan";
  item.text = `$(shield) Secura ${scannedFiles} file${scannedFiles === 1 ? "" : "s"} | ${findings} finding${
    findings === 1 ? "" : "s"
  }`;
  item.tooltip = `${modeLabel} completed on git-modified files.`;
}

type InsightsTerminal = {
  terminal: vscode.Terminal;
  log: (lines: string[]) => void;
};

function createInsightsTerminal(): InsightsTerminal {
  const writeEmitter = new vscode.EventEmitter<string>();
  const pty: vscode.Pseudoterminal = {
    onDidWrite: writeEmitter.event,
    open: () => {
      writeEmitter.fire("Secura Insights\r\n");
      writeEmitter.fire("Local scan summary for developers.\r\n\r\n");
      writeEmitter.fire("Detailed error: please go to http://localhost:8789.\r\n");
      writeEmitter.fire("AI fluency triage: issue, location, intent, reasoning, actions.\r\n\r\n");
    },
    close: () => {
      writeEmitter.dispose();
    }
  };

  const terminal = vscode.window.createTerminal({ name: "Secura Insights", pty });
  return {
    terminal,
    log: (lines: string[]) => {
      writeEmitter.fire(`${lines.join("\r\n")}\r\n\r\n`);
    }
  };
}

function withDetailedErrorLine(lines: string[]): string[] {
  return [
    ...lines,
    "Detailed error: please go to http://localhost:8789.",
    "AI fluency triage available at that URL (intent + context + actions)."
  ];
}

export function activate(context: vscode.ExtensionContext): void {
  const diagnostics = vscode.languages.createDiagnosticCollection("secura");
  const findings = new Map<string, Finding[]>();
  const modifiedFiles = new Set<string>();
  let gitRootPath: string | undefined;
  let insightsTerminal: InsightsTerminal | undefined;
  const statusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 30);
  statusBar.command = "secura.scanModifiedFiles";
  updateScanStatus(statusBar, "idle");
  statusBar.show();
  context.subscriptions.push(diagnostics);
  context.subscriptions.push(statusBar);
  context.subscriptions.push(
    vscode.window.onDidCloseTerminal(closed => {
      if (insightsTerminal && closed === insightsTerminal.terminal) {
        insightsTerminal = undefined;
      }
    })
  );

  const getInsightsTerminal = (): InsightsTerminal => {
    if (!insightsTerminal) {
      insightsTerminal = createInsightsTerminal();
    }
    return insightsTerminal;
  };

  const reportInsights = (mode: "manual" | "autosave" | "fix", scannedFiles: number): void => {
    const stats = getStats(context);
    const score = Math.max(0, 100 - stats.open * 20);
    const label =
      mode === "manual" ? "Manual modified-file scan" : mode === "autosave" ? "Auto-save modified-file scan" : "Remediation applied";
    const terminal = getInsightsTerminal();
    terminal.log(
      withDetailedErrorLine(
        [
          `[${new Date().toLocaleTimeString()}] ${label}`,
          `Scanned files: ${scannedFiles}`,
          `Open findings: ${stats.open}`,
          `Total findings detected: ${stats.found}`,
          `Total findings fixed: ${stats.fixed}`,
          `Security score: ${score}/100`
        ]
      )
    );
  };

  const refresh = async (document: vscode.TextDocument): Promise<void> => {
    const result = scanDocument(document);
    findings.set(document.uri.toString(), result);

    diagnostics.set(
      document.uri,
      result.map(finding => {
        const item = new vscode.Diagnostic(finding.range, finding.message, diagnosticSeverity(finding));
        item.source = "Secura";
        item.code = `hardcoded-${finding.provider}-secret`;
        return item;
      })
    );

    await recordScan(context, flattenSnapshots(findings));
    await persistFindingsForTriage(findings);
  };

  const refreshModifiedSet = async (folder: vscode.WorkspaceFolder): Promise<void> => {
    modifiedFiles.clear();
    const gitState = await getGitModifiedFiles(folder.uri.fsPath);
    gitRootPath = gitState.gitRoot;
    for (const filePath of gitState.files) {
      modifiedFiles.add(filePath.replace(/\\/g, "/"));
    }
  };

  const scanModifiedDocuments = async (
    folder: vscode.WorkspaceFolder,
    mode: "manual" | "autosave",
    targetRelativePath?: string
  ): Promise<number> => {
    await refreshModifiedSet(folder);
    const targets = targetRelativePath ? [targetRelativePath] : [...modifiedFiles];
    let scanned = 0;

    for (const relativePath of targets) {
      if (!modifiedFiles.has(relativePath)) continue;
      try {
        const document = await vscode.workspace.openTextDocument(vscode.Uri.joinPath(folder.uri, relativePath));
        await refresh(document);
        scanned += 1;
      } catch {
        // Ignore files removed/moved after git status.
      }
    }

    updateScanStatus(statusBar, mode, scanned, flattenSnapshots(findings).length);
    reportInsights(mode, scanned);
    return scanned;
  };

  vscode.workspace.textDocuments.forEach(document => void refresh(document));
  context.subscriptions.push(vscode.workspace.onDidOpenTextDocument(document => void refresh(document)));
  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument(async document => {
      const folder = vscode.workspace.getWorkspaceFolder(document.uri);
      if (!folder || !isSupportedPath(document.fileName)) return;

      try {
        await refreshModifiedSet(folder);
        const basePath = gitRootPath ?? folder.uri.fsPath;
        const relativePath = path.relative(basePath, document.uri.fsPath).replace(/\\/g, "/");
        if (!relativePath) return;
        if (relativePath.startsWith("../") || path.isAbsolute(relativePath)) return;
        if (!modifiedFiles.has(relativePath)) return;
        await scanModifiedDocuments(folder, "autosave", relativePath);
      } catch {
        return;
      }
    })
  );
  context.subscriptions.push(
    vscode.workspace.onDidCloseTextDocument(document => {
      findings.delete(document.uri.toString());
      diagnostics.delete(document.uri);
      void recordScan(context, flattenSnapshots(findings));
    })
  );

  context.subscriptions.push(
    vscode.languages.registerCodeActionsProvider(
      ["javascript", "typescript", "javascriptreact", "typescriptreact"],
      {
        provideCodeActions(document, range) {
          const finding = findingForRange(findings.get(document.uri.toString()) ?? [], range);
          if (!finding) return [];
          const action = new vscode.CodeAction(
            `Fix with Secura (${finding.secretType}) -> process.env.${finding.envVarName}`,
            vscode.CodeActionKind.QuickFix
          );
          action.command = { command: "secura.fixSecret", title: "Fix with Secura", arguments: [finding] };
          action.diagnostics = [...(diagnostics.get(document.uri) ?? [])];
          return [action];
        }
      },
      { providedCodeActionKinds: [vscode.CodeActionKind.QuickFix] }
    )
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("secura.fixSecret", async (candidate?: Finding) => {
      const finding = candidate ?? activeFinding(findings);
      if (!finding) {
        vscode.window.showInformationMessage("No Secura finding is selected. Place your cursor on a finding and retry.");
        return;
      }

      if (await applySecretFix(finding)) {
        await recordFix(context, finding);
        await refresh(finding.document);
        reportInsights("fix", 1);
        vscode.window
          .showInformationMessage(
            `Secura secured ${finding.secretType} using process.env.${finding.envVarName}. Rotate exposed secrets if committed.`,
            "Open dashboard"
          )
          .then(choice => {
            if (choice === "Open dashboard") openDashboard(context);
          });
      }
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("secura.openInsightsTerminal", async () => {
      const terminal = getInsightsTerminal();
      terminal.terminal.show(false);
      const stats = getStats(context);
      const score = Math.max(0, 100 - stats.open * 20);
      await persistFindingsForTriage(findings);
      const snapshots = flattenSnapshots(findings);
      const first = snapshots[0];
      const detailLines = first
        ? [
            `Issue: ${first.message}`,
            `Location: ${first.filePath}:${first.line}:${first.character}`,
            `Type: ${first.secretType} (${first.severity})`
          ]
        : ["Issue: No open finding details available."];

      terminal.log(
        withDetailedErrorLine(
          [
            `[${new Date().toLocaleTimeString()}] Insights terminal opened`,
            `Open findings: ${stats.open}`,
            `Total findings detected: ${stats.found}`,
            `Total findings fixed: ${stats.fixed}`,
            `Security score: ${score}/100`,
            ...detailLines
          ]
        )
      );
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("secura.scanModifiedFiles", async () => {
      const folder = vscode.workspace.workspaceFolders?.[0];
      if (!folder) {
        vscode.window.showErrorMessage("Secura needs an open workspace to scan modified files.");
        return;
      }

      let scannedCount = 0;
      try {
        scannedCount = await scanModifiedDocuments(folder, "manual");
      } catch {
        vscode.window.showErrorMessage("Secura could not read git status. Ensure this workspace is a git repository.");
        return;
      }

      if (scannedCount === 0) {
        vscode.window.showInformationMessage("No modified supported source files found in git status.");
        reportInsights("manual", 0);
        return;
      }

      const openFindings = flattenSnapshots(findings).length;
      getInsightsTerminal().terminal.show(false);
      void vscode.window
        .showInformationMessage(
          `Secura scanned ${scannedCount} modified file(s). Open findings: ${openFindings}.`,
          "Open insights terminal"
        )
        .then(choice => {
          if (choice === "Open insights terminal") {
            void vscode.commands.executeCommand("secura.openInsightsTerminal");
          }
        });
    })
  );

  context.subscriptions.push(vscode.commands.registerCommand("secura.openDashboard", () => openDashboard(context)));
}

export function deactivate(): void {}
