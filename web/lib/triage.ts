export type TriageFinding = {
  message?: string;
  secretType?: string;
  provider?: string;
  severity?: string;
  filePath?: string;
  fileName?: string;
  line?: number;
  character?: number;
  explanation?: string;
  envVarName?: string;
};

export type TriageCard = {
  issue_found: string;
  location: string;
  intent: string;
  reasoning: string;
  context_used: string[];
  mitre_tactic: string;
  summary: string;
  impact: string;
  severity: "Low" | "Medium" | "High";
  next_actions: string[];
  confidence: number;
  fluency_score: number;
};

export type TriageResult = {
  triage: TriageCard;
  mode: "ai-fluency-local" | "ai-fluency-llm" | "ai-fluency-local-fallback";
  ai_enabled: boolean;
};

function mapSeverity(severity: string | undefined): TriageCard["severity"] {
  const value = String(severity || "").toLowerCase();
  if (value === "critical" || value === "high") return "High";
  if (value === "medium") return "Medium";
  if (value === "low") return "Low";
  return "High";
}

function providerContext(provider: string | undefined): { mitre: string; blast: string } {
  switch (String(provider || "").toLowerCase()) {
    case "openai":
    case "anthropic":
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
    case "stripe":
      return {
        mitre: "T1552.001 - Unsecured Credentials: Credentials In Files",
        blast: "Payment fraud, customer data exposure, and account takeover"
      };
    case "slack":
      return {
        mitre: "T1552.001 - Unsecured Credentials: Credentials In Files",
        blast: "Workspace message access and social-engineering pivot"
      };
    case "google":
      return {
        mitre: "T1552.001 - Unsecured Credentials: Credentials In Files",
        blast: "Billed API abuse and cloud service misuse"
      };
    default:
      return {
        mitre: "T1552 - Unsecured Credentials",
        blast: "Credential reuse and lateral access risk"
      };
  }
}

function validateTriage(payload: Partial<TriageCard>): TriageCard {
  const nextActions = Array.isArray(payload.next_actions)
    ? payload.next_actions.filter((x) => typeof x === "string" && x.trim())
    : [];
  const contextUsed = Array.isArray(payload.context_used)
    ? payload.context_used.filter((x) => typeof x === "string" && x.trim()).slice(0, 5)
    : [];

  return {
    issue_found: typeof payload.issue_found === "string" ? payload.issue_found.trim() : "",
    location: typeof payload.location === "string" ? payload.location.trim() : "",
    intent: typeof payload.intent === "string" ? payload.intent.trim() : "",
    reasoning: typeof payload.reasoning === "string" ? payload.reasoning.trim() : "",
    context_used: contextUsed,
    mitre_tactic: typeof payload.mitre_tactic === "string" ? payload.mitre_tactic.trim() : "",
    summary: typeof payload.summary === "string" ? payload.summary.trim() : "",
    impact: typeof payload.impact === "string" ? payload.impact.trim() : "",
    severity: ["Low", "Medium", "High"].includes(String(payload.severity))
      ? (payload.severity as TriageCard["severity"])
      : "Medium",
    next_actions: nextActions.slice(0, 3),
    confidence: Number.isFinite(payload.confidence)
      ? Math.max(0, Math.min(100, Math.round(Number(payload.confidence))))
      : 50,
    fluency_score: Number.isFinite(payload.fluency_score)
      ? Math.max(0, Math.min(100, Math.round(Number(payload.fluency_score))))
      : 80
  };
}

export function fluentTriageFromFinding(finding: TriageFinding): TriageCard {
  const fileName =
    finding.fileName ||
    String(finding.filePath || "source file")
      .split(/[\\/]/)
      .pop() ||
    "source file";
  const location = `${finding.filePath || fileName}:${finding.line || "?"}:${finding.character || "?"}`;
  const envVar = finding.envVarName || "SECRET";
  const secretType = finding.secretType || "secret";
  const line = finding.line || "?";
  const ctx = providerContext(finding.provider);

  return validateTriage({
    issue_found: finding.message || `Hardcoded ${secretType} detected.`,
    location,
    intent: `Triage and remediate a hardcoded ${secretType} before it is committed or abused.`,
    reasoning:
      `Secura grounded this alert on a deterministic detector hit for ${secretType} in ${fileName}. ` +
      `Because the secret is embedded in source, the likely attacker path is credential theft from repo history or shared code, enabling ${ctx.blast}.`,
    context_used: [
      `file=${location}`,
      `provider=${finding.provider || "unknown"}`,
      `severity=${finding.severity || "unknown"}`,
      `secretType=${secretType}`,
      `detector=secura-web-scan`
    ],
    mitre_tactic: ctx.mitre,
    summary: `${secretType} found in ${fileName} at line ${line}.`,
    impact: finding.explanation || `Hardcoded secrets can be leaked and abused. Risk: ${ctx.blast}.`,
    severity: mapSeverity(finding.severity),
    next_actions: [
      `Open ${fileName}:${line} and confirm the hardcoded ${secretType}.`,
      `Replace the literal with process.env.${envVar} (or your platform secret store).`,
      "Rotate the exposed credential and verify it is not present in git history."
    ],
    confidence: 94,
    fluency_score: 88
  });
}

function findingContextBlock(finding: TriageFinding): string {
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

function extractJson(text: string): Partial<TriageCard> | null {
  if (!text) return null;
  try {
    return JSON.parse(text) as Partial<TriageCard>;
  } catch {
    const match = text.match(/\{[\s\S]*\}/);
    if (!match) return null;
    try {
      return JSON.parse(match[0]) as Partial<TriageCard>;
    } catch {
      return null;
    }
  }
}

async function triageFindingWithAi(finding: TriageFinding, apiKey: string): Promise<TriageCard> {
  const model = process.env.OPENAI_MODEL || "gpt-4.1-mini";
  const prompt = [
    "You are Secura, an AI-fluent security engineer for developers.",
    "Demonstrate AI fluency: understand intent, use grounded context, explain risk, and recommend concrete actions.",
    "Return only valid JSON with exactly these fields:",
    "issue_found, location, intent, reasoning, context_used, mitre_tactic, summary, impact, severity, next_actions, confidence, fluency_score",
    "",
    "Constraints:",
    "- Prefer grounded finding facts over speculation.",
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
      Authorization: `Bearer ${apiKey}`
    },
    body: JSON.stringify({
      model,
      response_format: { type: "json_object" },
      messages: [
        { role: "system", content: prompt },
        {
          role: "user",
          content: ["Grounded Secura finding snapshot:", findingContextBlock(finding)].join("\n")
        }
      ],
      temperature: 0.2
    })
  });

  if (!response.ok) {
    const errText = await response.text();
    throw new Error(`OpenAI API request failed (${response.status}): ${errText.slice(0, 180)}`);
  }

  const payload = (await response.json()) as {
    choices?: Array<{ message?: { content?: string } }>;
  };
  const parsed = extractJson(payload?.choices?.[0]?.message?.content || "");
  if (!parsed) throw new Error("Model response could not be parsed as JSON.");
  return validateTriage(parsed);
}

export async function triageFinding(finding: TriageFinding): Promise<TriageResult> {
  if (!finding || (!finding.message && !finding.secretType && !finding.filePath)) {
    throw new Error("finding is required.");
  }

  const local = fluentTriageFromFinding(finding);
  const apiKey = process.env.OPENAI_API_KEY;

  if (!apiKey) {
    return { triage: local, mode: "ai-fluency-local", ai_enabled: false };
  }

  try {
    const triage = await triageFindingWithAi(finding, apiKey);
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
  } catch {
    return { triage: local, mode: "ai-fluency-local-fallback", ai_enabled: true };
  }
}
