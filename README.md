# Secura

Local-first security companion for developers. Catch hardcoded secrets before they ship — in the editor or on the web.

**Live:** [https://secura-ai-rho.vercel.app/](https://secura-ai-rho.vercel.app/) (free, no signup)

## What it does

- Scans public GitHub repos and local workspaces for leaked credentials
- Detects common API keys and tokens (OpenAI, Anthropic, GitHub, AWS, Stripe, Slack, Google), private keys, and password-like assignments
- Shows file, line, severity, and a redacted risk explanation
- AI triage on each web finding (intent, MITRE, next actions)
- VS Code / Cursor extension with one-click remediation (`process.env` + `.env` / `.gitignore`)

## Web

```bash
npm install
npm run web
```

Open [http://localhost:3000](http://localhost:3000), paste a public GitHub URL, and scan.

## Extension

```bash
npm install
npm run compile
```

Press `F5` for the Extension Development Host, or `npm run package` and install the VSIX.

Then run **Secura: Scan modified files for security issues** and use **Fix with Secura** on findings.

## Security

- Extension scanning and remediation stay local to the editor
- The extension does not send secret values to external AI services
- The web app only reads public GitHub file contents (or local files when you run it yourself)
- Use fake secrets in tests and demos — never real credentials
