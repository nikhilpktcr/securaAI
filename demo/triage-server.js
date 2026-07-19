const http = require("http");
const fs = require("fs");
const path = require("path");

function resolvePort() {
  const args = process.argv.slice(2);
  let cliPort = "";

  for (let i = 0; i < args.length; i += 1) {
    const arg = args[i];
    if (arg.startsWith("--port=")) {
      cliPort = arg.split("=")[1] || "";
      break;
    }
    if (arg === "--port" && args[i + 1]) {
      cliPort = args[i + 1];
      break;
    }
  }

  const raw = cliPort || process.env.PORT || "8787";
  const parsed = Number(raw);
  if (!Number.isInteger(parsed) || parsed < 1 || parsed > 65535) {
    return 8787;
  }
  return parsed;
}

const PORT = resolvePort();
const OPENAI_API_KEY = process.env.OPENAI_API_KEY;
const MODEL = process.env.OPENAI_MODEL || "gpt-4.1-mini";
const FINDINGS_PATH = path.join(__dirname, "latest-findings.json");

const HTML_PATH = path.join(__dirname, "triage.html");
const html = fs.readFileSync(HTML_PATH, "utf8");

function sendJson(res, status, data) {
  const body = JSON.stringify(data);
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": Buffer.byteLength(body)
  });
  res.end(body);
}

function sanitizeAlertText(alertText) {
  return String(alertText || "").slice(0, 12000).trim();
}

function safeParseJson(raw) {
  try {
    return JSON.parse(raw || "{}");
  } catch (_err) {
    return {};
  }
}

function extractJson(text) {
  if (!text) return null;

  try {
    return JSON.parse(text);
  } catch (_err) {
    const match = text.match(/\{[\s\S]*\}/);
    if (!match) return null;
    try {
      return JSON.parse(match[0]);
    } catch (_err2) {
      return null;
    }
  }
}

function validateTriage(payload) {
  const candidate = payload || {};
  const nextActions = Array.isArray(candidate.next_actions)
    ? candidate.next_actions.filter((x) => typeof x === "string" && x.trim())
    : [];
  const contextUsed = Array.isArray(candidate.context_used)
    ? candidate.context_used.filter((x) => typeof x === "string" && x.trim()).slice(0, 5)
    : [];

  return {
    issue_found: typeof candidate.issue_found === "string" ? candidate.issue_found.trim() : "",
    location: typeof candidate.location === "string" ? candidate.location.trim() : "",
    intent: typeof candidate.intent === "string" ? candidate.intent.trim() : "",
    reasoning: typeof candidate.reasoning === "string" ? candidate.reasoning.trim() : "",
    context_used: contextUsed,
    mitre_tactic: typeof candidate.mitre_tactic === "string" ? candidate.mitre_tactic.trim() : "",
    summary: typeof candidate.summary === "string" ? candidate.summary.trim() : "",
    impact: typeof candidate.impact === "string" ? candidate.impact.trim() : "",
    severity: ["Low", "Medium", "High"].includes(candidate.severity) ? candidate.severity : "Medium",
    next_actions: nextActions.slice(0, 3),
    confidence: Number.isFinite(candidate.confidence)
      ? Math.max(0, Math.min(100, Math.round(candidate.confidence)))
      : 50,
    fluency_score: Number.isFinite(candidate.fluency_score)
      ? Math.max(0, Math.min(100, Math.round(candidate.fluency_score)))
      : 80
  };
}

function readLatestFindings() {
  try {
    if (!fs.existsSync(FINDINGS_PATH)) {
      return { updatedAt: null, open: 0, findings: [] };
    }
    const parsed = safeParseJson(fs.readFileSync(FINDINGS_PATH, "utf8"));
    const findings = Array.isArray(parsed.findings) ? parsed.findings : [];
    return {
      updatedAt: parsed.updatedAt || null,
      open: Number.isFinite(parsed.open) ? parsed.open : findings.length,
      findings
    };
  } catch (_err) {
    return { updatedAt: null, open: 0, findings: [] };
  }
}

function mapSeverity(severity) {
  const value = String(severity || "").toLowerCase();
  if (value === "critical" || value === "high") return "High";
  if (value === "medium") return "Medium";
  if (value === "low") return "Low";
  return "High";
}

function providerContext(provider) {
  switch (String(provider || "").toLowerCase()) {
    case "openai":
      return {
        mitre: "T1552.001 - Unsecured Credentials: Credentials In Files",
        blast: "API abuse, data exfiltration, and unexpected billing risk"
      };
    case "github":
      return {
        mitre: "T1552.001 - Unsecured Credentials: Credentials In Files",
        blast: "Repository takeover, workflow abuse, and org secret exposure"
      };
    case "aws":
      return {
        mitre: "T1078.004 - Valid Accounts: Cloud Accounts",
        blast: "Unauthorized cloud access and resource takeover"
      };
    default:
      return {
        mitre: "T1552 - Unsecured Credentials",
        blast: "Credential reuse and lateral access risk"
      };
  }
}

function fluentTriageFromFinding(finding) {
  if (!finding) return null;

  const location = `${finding.filePath || finding.fileName || "unknown"}:${finding.line || "?"}:${finding.character || "?"}`;
  const envVar = finding.envVarName || "SECRET";
  const secretType = finding.secretType || "secret";
  const fileName = finding.fileName || "source file";
  const line = finding.line || "?";
  const ctx = providerContext(finding.provider);

  return validateTriage({
    issue_found: finding.message || `Hardcoded ${secretType} detected.`,
    location,
    intent: `Triage and remediate a hardcoded ${secretType} before it is committed or abused.`,
    reasoning:
      `Secura grounded this alert on a deterministic local detector hit for ${secretType} in ${fileName}. ` +
      `Because the secret is embedded in source, the likely attacker path is credential theft from repo history or shared code, enabling ${ctx.blast}.`,
    context_used: [
      `file=${location}`,
      `provider=${finding.provider || "unknown"}`,
      `severity=${finding.severity || "unknown"}`,
      `secretType=${secretType}`,
      `detector=local-secret-scan`
    ],
    mitre_tactic: ctx.mitre,
    summary: `${secretType} found in ${fileName} at line ${line}.`,
    impact: finding.explanation || `Hardcoded secrets can be leaked and abused. Risk: ${ctx.blast}.`,
    severity: mapSeverity(finding.severity),
    next_actions: [
      `Open ${fileName}:${line} and confirm the hardcoded ${secretType}.`,
      `Replace the literal with process.env.${envVar} using Secura quick-fix.`,
      "Rotate the exposed credential and verify it is not present in git history."
    ],
    confidence: 94,
    fluency_score: 88
  });
}

function fluentTriageFromAlertText(alertText) {
  const findings = readLatestFindings().findings;
  if (findings.length > 0) {
    return fluentTriageFromFinding(findings[0]);
  }

  return validateTriage({
    issue_found: "Security finding reported by Secura Insights.",
    location: "See Secura Insights terminal for source file location.",
    intent: "Explain the open finding and recommend the safest next remediation steps.",
    reasoning:
      "No structured finding file was available, so Secura used Insights summary text as weak context. " +
      "Run a Secura scan to ground triage on exact file/line evidence.",
    context_used: ["source=insights-summary", "detector=unavailable"],
    mitre_tactic: "T1552 - Unsecured Credentials",
    summary: String(alertText).slice(0, 180),
    impact: "Open findings indicate potential secret exposure that needs remediation.",
    severity: "High",
    next_actions: [
      "Run Secura: Scan modified files for security issues.",
      "Open the flagged file from Insights and inspect the secret.",
      "Apply Secura quick-fix to move the value into process.env."
    ],
    confidence: 68,
    fluency_score: 72
  });
}

function findingContextBlock(finding) {
  if (!finding) return "No local finding snapshot available.";
  return JSON.stringify(
    {
      message: finding.message,
      secretType: finding.secretType,
      provider: finding.provider,
      severity: finding.severity,
      filePath: finding.filePath,
      fileName: finding.fileName,
      line: finding.line,
      character: finding.character,
      explanation: finding.explanation,
      envVarName: finding.envVarName
    },
    null,
    2
  );
}

async function triageAlertWithAi(alertText, finding) {
  const prompt = [
    "You are Secura, an AI-fluent security engineer for developers.",
    "Demonstrate AI fluency: understand intent, use grounded context, explain risk, and recommend concrete actions.",
    "Return only valid JSON with exactly these fields:",
    "issue_found, location, intent, reasoning, context_used, mitre_tactic, summary, impact, severity, next_actions, confidence, fluency_score",
    "",
    "Constraints:",
    "- Prefer grounded local finding facts over speculation.",
    "- location must include file path and line when available.",
    "- context_used: 2-5 short evidence strings used for the decision.",
    "- reasoning: 2-3 sentences explaining why this matters now.",
    "- intent: one sentence describing the developer goal you inferred.",
    "- mitre_tactic: best matching MITRE ATT&CK technique id + name.",
    "- severity must be one of: Low, Medium, High",
    "- next_actions: exactly 3 specific actions ordered by priority",
    "- confidence and fluency_score: integers 0-100",
    "- Do not invent file paths, IPs, or credentials that are not present."
  ].join("\n");

  const response = await fetch("https://api.openai.com/v1/chat/completions", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${OPENAI_API_KEY}`
    },
    body: JSON.stringify({
      model: MODEL,
      response_format: {
        type: "json_schema",
        json_schema: {
          name: "ai_fluency_triage_card",
          strict: true,
          schema: {
            type: "object",
            properties: {
              issue_found: { type: "string" },
              location: { type: "string" },
              intent: { type: "string" },
              reasoning: { type: "string" },
              context_used: {
                type: "array",
                minItems: 2,
                maxItems: 5,
                items: { type: "string" }
              },
              mitre_tactic: { type: "string" },
              summary: { type: "string" },
              impact: { type: "string" },
              severity: { type: "string", enum: ["Low", "Medium", "High"] },
              next_actions: {
                type: "array",
                minItems: 3,
                maxItems: 3,
                items: { type: "string" }
              },
              confidence: { type: "integer", minimum: 0, maximum: 100 },
              fluency_score: { type: "integer", minimum: 0, maximum: 100 }
            },
            required: [
              "issue_found",
              "location",
              "intent",
              "reasoning",
              "context_used",
              "mitre_tactic",
              "summary",
              "impact",
              "severity",
              "next_actions",
              "confidence",
              "fluency_score"
            ],
            additionalProperties: false
          }
        }
      },
      messages: [
        { role: "system", content: prompt },
        {
          role: "user",
          content: [
            "Grounded Secura finding snapshot:",
            findingContextBlock(finding),
            "",
            "Developer/alert text:",
            alertText
          ].join("\n")
        }
      ],
      temperature: 0.2
    })
  });

  if (!response.ok) {
    const errText = await response.text();
    throw new Error(`OpenAI API request failed (${response.status}): ${errText}`);
  }

  const payload = await response.json();
  const text = payload?.choices?.[0]?.message?.content;
  const parsed = extractJson(text);
  if (!parsed) {
    throw new Error("Model response could not be parsed as JSON.");
  }

  return validateTriage(parsed);
}

async function triageAlert(alertText) {
  const findings = readLatestFindings().findings;
  const finding = findings[0];
  const local = fluentTriageFromAlertText(alertText);

  if (!OPENAI_API_KEY) {
    return { triage: local, mode: "ai-fluency-local", ai_enabled: false };
  }

  try {
    const triage = await triageAlertWithAi(alertText, finding);
    return {
      triage: {
        ...triage,
        issue_found: triage.issue_found || local.issue_found,
        location: triage.location || local.location,
        context_used: triage.context_used.length ? triage.context_used : local.context_used
      },
      mode: "ai-fluency-llm",
      ai_enabled: true
    };
  } catch (_err) {
    return { triage: local, mode: "ai-fluency-local-fallback", ai_enabled: true };
  }
}

const server = http.createServer(async (req, res) => {
  if (req.method === "GET" && (req.url === "/" || req.url?.startsWith("/?"))) {
    res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
    res.end(html);
    return;
  }

  if (req.method === "GET" && req.url === "/findings") {
    sendJson(res, 200, readLatestFindings());
    return;
  }

  if (req.method === "POST" && req.url === "/triage") {
    let body = "";

    req.on("data", (chunk) => {
      body += chunk;
      if (body.length > 20000) {
        req.socket.destroy();
      }
    });

    req.on("end", async () => {
      try {
        const parsedBody = safeParseJson(body);
        const alertText = sanitizeAlertText(parsedBody.alertText);
        if (!alertText) {
          sendJson(res, 400, { error: "alertText is required." });
          return;
        }

        const result = await triageAlert(alertText);
        sendJson(res, 200, result);
      } catch (error) {
        sendJson(res, 500, { error: error.message || "Unexpected server error." });
      }
    });
    return;
  }

  sendJson(res, 404, { error: "Not found" });
});

server.on("error", (error) => {
  if (error && error.code === "EADDRINUSE") {
    console.error(
      [
        `Port ${PORT} is already in use.`,
        "Run one of the following, then retry:",
        `- Free the port: taskkill /PID <pid> /F`,
        `- Or use another port:`,
        `  npm arg (works everywhere): npm run demo:triage -- --port=8788`,
        `  PowerShell: $env:PORT=8788; npm run demo:triage`,
        `  bash: PORT=8788 npm run demo:triage`
      ].join("\n")
    );
    process.exit(1);
    return;
  }

  console.error("Server failed to start:", error);
  process.exit(1);
});

server.listen(PORT, () => {
  console.log(`Secura AI fluency triage running on http://localhost:${PORT}`);
});
