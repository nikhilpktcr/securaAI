# Secura

Local-first security companion for developers. Catch hardcoded secrets before they ship.

**Live (public repos):** [https://secura-ai-rho.vercel.app/](https://secura-ai-rho.vercel.app/) — free, no signup

---

## Which path should I use?

| Your repo | Use this |
| --- | --- |
| **Public GitHub repo** | [Web app](https://secura-ai-rho.vercel.app/) — paste the URL and scan |
| **Private repo** | **VS Code / Cursor extension** — scan locally on your machine |

Private repos cannot be read by the free web scanner. Use the extension so scanning stays on your laptop.

---

## Public repos — web (score + issues)

1. Open [https://secura-ai-rho.vercel.app/](https://secura-ai-rho.vercel.app/)
2. Paste a public GitHub URL (example: `https://github.com/owner/repo`)
3. Click **Scan free**
4. Review the security score, files scanned, and findings

No account required.

---

## Private repos — extension (step by step)

### 1. Install dependencies

```bash
npm install
```

### 2. Build the extension

```bash
npm run compile
npm run package
```

This creates a VSIX file such as `secura-ai-0.0.1.vsix` in the project root.

### 3. Install in VS Code or Cursor

1. Open **VS Code** or **Cursor**
2. Open the Command Palette:
   - Windows / Linux: `Ctrl+Shift+P`
   - macOS: `Cmd+Shift+P`
3. Run: **Extensions: Install from VSIX...**
4. Select `secura-ai-0.0.1.vsix`
5. Reload the window if prompted

### 4. Open your private project

1. Clone or open your **private** repository locally
2. In VS Code / Cursor: **File → Open Folder...**
3. Select the project folder

Secura scans the files on disk — it does not need your repo to be public.

### 5. Scan for secrets

1. Open the Command Palette (`Ctrl+Shift+P` / `Cmd+Shift+P`)
2. Run: **Secura: Scan modified files for security issues**
3. Check:
   - Inline warnings in the editor
   - Status bar: `Secura … files | … findings`
   - **Secura: Open security dashboard** for a summary
   - **Secura: Open insights terminal** for a local scan report

Tip: Secura also scans on save for supported files.

### 6. Fix a finding

1. Click a secret warning in the editor (lightbulb / quick fix)
2. Choose **Fix with Secura (...)**
3. Review the preview, then confirm **Apply secure fix**

Secura will:

- Replace the hardcoded value with `process.env.<VAR_NAME>`
- Add the value to `.env`
- Add a placeholder to `.env.example`
- Ensure `.env` is listed in `.gitignore`

### 7. (Optional) Develop the extension locally

For contributors:

```bash
npm install
npm run compile
```

Then press **F5** to launch the Extension Development Host and test against any local folder (public or private).

---

## What Secura detects

- OpenAI / Anthropic API keys
- GitHub tokens
- AWS access key IDs and secret access keys
- Stripe / Slack / Google keys
- Private key blocks
- Password-like hardcoded assignments

Findings include file path, line, severity, and a redacted explanation.

---

## Security

- **Extension:** scanning and remediation stay local; secret values are not sent to external AI services
- **Web:** only reads **public** GitHub file contents
- Use fake secrets in tests — never real production credentials

---

## Local web (optional)

Run the web platform on your machine:

```bash
npm install
npm run web
```

Open [http://localhost:3000](http://localhost:3000)

---

## Scripts

| Script | Description |
| --- | --- |
| `npm run compile` | Build the extension |
| `npm run package` | Create the `.vsix` installer |
| `npm run web` | Start the local web app |
| `npm test` | Run tests |
| `npm run deploy:web` | Deploy `web/` to Vercel |
