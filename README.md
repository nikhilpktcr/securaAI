# Secura AI

Security companion for developers: a VS Code/Cursor extension plus a live web platform that scans linked repositories for hardcoded secrets.

## Product surfaces

| Surface | What it does |
| --- | --- |
| **VS Code / Cursor extension** | Local secret detection, one-click remediation, dashboard, Insights terminal |
| **Live web platform** (`web/`) | Login → link GitHub/local repo → scan modified files → review findings |
| **AI fluency triage** (`demo/`) | Alert → grounded triage card (issue, location, intent, reasoning, actions) |

## Features

- Detects:
  - OpenAI API keys
  - GitHub tokens
  - AWS access key IDs
  - Password-like hardcoded assignments
- Explains risk with redacted previews
- One-click remediation (extension):
  - Replaces literal with `process.env.<VAR_NAME>`
  - Updates `.env`, `.env.example`, `.gitignore`
- Web platform findings: file path, line, severity, explanation
- AI fluency triage: intent, context used, MITRE mapping, next actions, confidence

## Security boundaries

- Extension detection/remediation runs locally in the editor host
- Secret values are not sent to external AI services by the extension
- Web/Vercel scanning reads public GitHub file contents (or local git files when running `npm run web`)
- Use fake secrets only in demos and tests

---

## Quick start

```bash
npm install
npm run compile
```

### Demo login (web)

- Email: `demo@secura.ai`
- Password: `secura123`

---

## 1) Live web platform (local)

```bash
npm run web
```

Open [http://localhost:3000](http://localhost:3000)

If port `3000` is busy:

```bash
npm run web -- --port=3001
```

Flow:

1. Log in with demo credentials
2. Link a repository
   - Local: filesystem git path
   - Cloud/Vercel: GitHub URL such as `https://github.com/nikhilpktcr/securaAI`
3. Click **Scan modified files**
4. Review findings (issue + location)

TypeScript APIs live in:

- `web/api/*.ts`
- `web/lib/*.ts`

---

## 2) Deploy web platform to Vercel

1. Login:

```bash
npx vercel login
```

2. Deploy (`web` is the project root):

```bash
npx vercel --cwd web
```

Production:

```bash
npm run deploy:web
```

Or in the Vercel dashboard:

1. Import `nikhilpktcr/securaAI`
2. Set **Root Directory** to `web`
3. Deploy

Optional environment variables:

| Name | Purpose |
| --- | --- |
| `SESSION_SECRET` | Cookie signing secret |
| `GITHUB_TOKEN` | Private repos / higher GitHub API rate limits |

On Vercel, link a **public GitHub URL** (local filesystem paths are not available in serverless).

---

## 3) VS Code / Cursor extension

### Install from VSIX

```bash
npm install
npm run package
```

Then: Command Palette → **Extensions: Install from VSIX...** → select `secura-ai-0.0.1.vsix`

### Run in development

```bash
npm install
npm run compile
```

Open this folder and press `F5` (Extension Development Host).

### Extension usage

1. Open a JS/TS file with a fake secret (for example `demo/app.js`)
2. Save / run **Secura: Scan modified files for security issues**
3. Use lightbulb quick fix: **Fix with Secura (...)**
4. Open **Secura: Open security dashboard**
5. Open **Secura: Open insights terminal** for score + link to detailed triage

Insights terminal points to the AI fluency page when findings are open:

`Detailed error: please go to http://localhost:8789.`

---

## 4) AI fluency triage demo

```bash
npm run app -- --port=8789
```

Open [http://localhost:8789](http://localhost:8789)

- Works locally without an API key (grounded finding details)
- Optional LLM enrichment:

```bash
export OPENAI_API_KEY="sk-..."
npm run app -- --port=8789
```

Port busy? Free it or pick another:

```bash
# Git Bash
netstat -ano | rg ":8789"
taskkill //PID <pid> //F

# Or
npm run app -- --port=8790
```

Triage card includes:

- Issue found + location
- Understood intent
- AI reasoning + context used
- MITRE tactic
- Top 3 actions
- Confidence / fluency score

---

## Scripts

| Script | Description |
| --- | --- |
| `npm run compile` | Compile extension TypeScript |
| `npm run compile:web` | Install/build web TypeScript libs |
| `npm run web` | Start local web platform on port 3000 |
| `npm run app` | Start AI fluency triage demo |
| `npm run demo:triage` | Start triage server only |
| `npm run package` | Build VSIX |
| `npm test` | Run tests |
| `npm run deploy:web` | Deploy `web/` to Vercel production |

---

## Verification

```bash
npm test
```

---

## Demo script (hackathon)

1. Show extension scan + quick fix on `demo/app.js`
2. Open Insights terminal (score + detail URL)
3. Run `npm run web` → login → link repo → scan findings
4. Open `http://localhost:8789` for AI fluency triage card
5. (Optional) Deploy `web/` to Vercel and scan a public GitHub repo

Pitch:

> Secura starts as a trusted local security companion, then becomes an AI-fluent platform that links repos, explains risk, and guides remediation.
