import * as vscode from "vscode";
import { getStats } from "./stats";

function card(label: string, value: string): string {
  return `<section style="background:#151d2d;padding:18px;border-radius:12px;min-width:140px"><small>${label}</small><h2>${value}</h2></section>`;
}

function capitalize(value: string): string {
  return value.charAt(0).toUpperCase() + value.slice(1);
}

export function openDashboard(context: vscode.ExtensionContext): void {
  const panel = vscode.window.createWebviewPanel("securaDashboard", "Secura Security Dashboard", vscode.ViewColumn.Beside, {});
  const stats = getStats(context);
  const score = Math.max(0, 100 - stats.open * 20);

  const severityList = Object.entries(stats.findingsBySeverity)
    .map(([severity, count]) => `<li>${capitalize(severity)}: ${count}</li>`)
    .join("");

  const providerList = Object.entries(stats.findingsByProvider)
    .map(([provider, count]) => `<li>${provider.toUpperCase()}: ${count}</li>`)
    .join("");

  const auditList = stats.audit.length
    ? stats.audit
        .map(item => `<li><code>${new Date(item.timestamp).toLocaleTimeString()}</code> ${item.summary}</li>`)
        .join("")
    : "<li>No audit events yet.</li>";

  panel.webview.html = `<!doctype html>
<html>
<body style="font-family:system-ui;background:#0c111b;color:#e6edf3;padding:28px">
  <main style="max-width:860px">
    <p style="color:#65d9b7;letter-spacing:2px">SECURA AI</p>
    <h1>Developer Security Dashboard</h1>
    <div style="display:flex;gap:12px;flex-wrap:wrap">
      ${card("SECURITY SCORE", `${score} / 100`)}
      ${card("SECRETS FOUND", String(stats.found))}
      ${card("SECRETS FIXED", String(stats.fixed))}
      ${card("OPEN ISSUES", String(stats.open))}
    </div>
    <section style="display:flex;gap:36px;flex-wrap:wrap;margin-top:22px">
      <div>
        <h3>Open by severity</h3>
        <ul style="line-height:1.8">${severityList || "<li>None</li>"}</ul>
      </div>
      <div>
        <h3>Open by provider</h3>
        <ul style="line-height:1.8">${providerList || "<li>None</li>"}</ul>
      </div>
    </section>
    <h3>Audit trail (redacted)</h3>
    <ul style="line-height:1.8">${auditList}</ul>
    <p style="color:#9ba8bd">
      Detection and remediation previews run locally. Secret values stay on your machine and are not sent to AI services.
    </p>
  </main>
</body>
</html>`;
}
