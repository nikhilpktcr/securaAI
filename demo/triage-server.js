const http = require("http");
const fs = require("fs");
const path = require("path");

const PORT = Number(process.env.PORT || 8787);
const OPENAI_API_KEY = process.env.OPENAI_API_KEY;
const MODEL = process.env.OPENAI_MODEL || "gpt-4.1-mini";

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

function extractJson(text) {
  if (!text) return null;

  try {
    return JSON.parse(text);
  } catch (_err) {
    // Attempt to parse JSON object if model adds surrounding text.
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

  return {
    summary: typeof candidate.summary === "string" ? candidate.summary.trim() : "",
    impact: typeof candidate.impact === "string" ? candidate.impact.trim() : "",
    severity: ["Low", "Medium", "High"].includes(candidate.severity) ? candidate.severity : "Medium",
    next_actions: nextActions.slice(0, 3),
    confidence: Number.isFinite(candidate.confidence) ? Math.max(0, Math.min(100, Math.round(candidate.confidence))) : 50
  };
}

async function triageAlert(alertText) {
  if (!OPENAI_API_KEY) {
    throw new Error("OPENAI_API_KEY is not set. Export it before starting the demo.");
  }

  const prompt = [
    "You are a SOC triage assistant.",
    "Return only valid JSON with exactly these fields:",
    "summary, impact, severity, next_actions, confidence",
    "",
    "Constraints:",
    "- summary: max 40 words",
    "- impact: max 50 words",
    "- severity must be one of: Low, Medium, High",
    "- next_actions: array with exactly 3 specific actions ordered by priority",
    "- confidence: integer from 0 to 100",
    "- Do not fabricate unavailable evidence."
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
          name: "triage_card",
          strict: true,
          schema: {
            type: "object",
            properties: {
              summary: { type: "string" },
              impact: { type: "string" },
              severity: { type: "string", enum: ["Low", "Medium", "High"] },
              next_actions: {
                type: "array",
                minItems: 3,
                maxItems: 3,
                items: { type: "string" }
              },
              confidence: { type: "integer", minimum: 0, maximum: 100 }
            },
            required: ["summary", "impact", "severity", "next_actions", "confidence"],
            additionalProperties: false
          }
        }
      },
      messages: [
        { role: "system", content: prompt },
        { role: "user", content: `Alert:\n${alertText}` }
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

const server = http.createServer(async (req, res) => {
  if (req.method === "GET" && req.url === "/") {
    res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
    res.end(html);
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
        const parsedBody = JSON.parse(body || "{}");
        const alertText = sanitizeAlertText(parsedBody.alertText);
        if (!alertText) {
          sendJson(res, 400, { error: "alertText is required." });
          return;
        }

        const triage = await triageAlert(alertText);
        sendJson(res, 200, { triage });
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
  console.log(`Secura AI triage demo running on http://localhost:${PORT}`);
});
