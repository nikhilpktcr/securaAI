import * as vscode from "vscode";
import { detectSecrets } from "./detectors";
import { Finding } from "./types";

export function scanDocument(document: vscode.TextDocument): Finding[] {
  if (!["javascript", "typescript", "javascriptreact", "typescriptreact"].includes(document.languageId)) {
    return [];
  }

  const text = document.getText();
  return detectSecrets(text).map(detection => ({
    ...detection,
    document,
    range: new vscode.Range(document.positionAt(detection.start), document.positionAt(detection.end))
  }));
}
