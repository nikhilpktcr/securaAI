# Secura AI

Local-first VS Code extension for detecting hardcoded secrets and applying reviewable one-click remediation.

## What this MVP includes

- Deterministic local detection for:
  - OpenAI API keys
  - GitHub tokens
  - AWS access key IDs
  - Password-like hardcoded assignments
- Risk explanation for each finding with redacted value previews.
- One-click remediation that:
  - Replaces the literal with `process.env.<VAR_NAME>`
  - Adds/updates `.env`
  - Adds/updates `.env.example`
  - Ensures `.env` is ignored in `.gitignore`
- Local redacted audit trail and VS Code dashboard.

## Security boundaries

- Detection and remediation previews run locally in the extension host.
- Secret values are never sent to external AI services.
- This hackathon MVP uses local workspace files as the secret store (`.env`).
- Use fake secrets only in demos and tests.

## Installation guide

### Option A: Install from VSIX (recommended for testing)

1. Build the package:

```powershell
npm install
npm run package
```

2. Install in VS Code:
   - Open Command Palette -> **Extensions: Install from VSIX...**
   - Select `secura-ai-0.0.1.vsix`

Or install from terminal:

```powershell
code --install-extension "C:\Users\nikhi\Documents\Codex\2026-07-19\n\secura-ai-0.0.1.vsix"
```

3. Install in Cursor:
   - Open Command Palette -> **Extensions: Install from VSIX...**
   - Select `secura-ai-0.0.1.vsix`
   - Reload Cursor if prompted

### Option B: Run as extension under development

```powershell
npm install
npm run compile
```

Open this folder in VS Code or Cursor and press `F5` to launch an Extension Development Host.

## Running guide

1. Open any JS/TS file (or `demo/app.js`) with fake secret values.
2. Save the file to trigger auto-scan for git-modified files.
3. Check diagnostics in the editor for Secura findings.
4. Use the lightbulb quick fix: **Fix with Secura (...)**.
5. Review and approve the remediation preview.
6. Confirm updates in:
   - source file (`process.env.<VAR>`)
   - `.env`
   - `.env.example`
   - `.gitignore`
7. Open command: **Secura: Open security dashboard**.

## Scan modified files

Use command palette: **Secura: Scan modified files for security issues**.

- Secura reads `git status --porcelain`.
- It scans modified JS/TS files in the current repository.
- It also auto-scans on save, but only for files currently marked as git-modified.
- Findings are surfaced as editor diagnostics and shown in the dashboard.
- Status bar shows last scan result (`files scanned` and `open findings`) and can be clicked to run a manual scan.

## Insights terminal

Use command palette: **Secura: Open insights terminal**.

- Opens a dedicated terminal tab named `Secura Insights`.
- Logs scan/fix summaries with:
  - scanned file count
  - open findings
  - total detected and fixed findings
  - current security score

## Hackathon AI triage demo

This repo now includes a lightweight web demo for the "Alert -> AI Triage Card" flow.

1. Set your API key:

```powershell
$env:OPENAI_API_KEY="your_key_here"
```

2. Start the demo server:

```powershell
npm run demo:triage
```

If port `8787` is busy, run on a different port:

```powershell
$env:PORT=8788
npm run demo:triage
```

3. Open [http://localhost:8787](http://localhost:8787), paste an alert, and click **Generate Triage Card**.

The card returns:
- what happened
- why it matters
- severity
- top 3 next actions
- confidence score

## Verification

```powershell
npm test
```

## Future scope

- Today (MVP): deterministic, developer-safe security companion inside the editor.
- Future scope: an AI agent becomes an optional copilot for secret classification, remediation suggestions, and policy guidance.
- Why phased: teams adopt AI gradually, so trust is built first through transparent, local-first behavior.

Pitch line:

> "Secura starts as a reliable security companion developers trust today, and evolves into an AI security agent as teams become ready to delegate more decisions."

## Demo script (hackathon flow)

1. Open `demo/app.js` (or another JS/TS file with fake secrets).
2. Wait for Secura diagnostics to appear.
3. Trigger the lightbulb quick-fix: **Fix with Secura**.
4. Review the remediation preview and confirm.
5. Show:
   - Source replacement to `process.env.<VAR>`
   - Updated `.env`, `.env.example`, `.gitignore`
   - Dashboard audit trail via command **Secura: Open security dashboard**.
