const test = require("node:test");
const assert = require("node:assert/strict");
const { fluentTriageFromFinding } = require("../web/dist/lib/triage.js");

test("grounds triage card from a web finding", () => {
  const triage = fluentTriageFromFinding({
    message: "Secura: Hardcoded OpenAI API key detected.",
    secretType: "OpenAI API key",
    provider: "openai",
    severity: "critical",
    filePath: "demo/app.js",
    line: 2,
    character: 27,
    explanation: "OpenAI keys grant direct API usage.",
    envVarName: "OPENAI_API_KEY"
  });

  assert.match(triage.location, /demo\/app\.js:2:27/);
  assert.equal(triage.severity, "High");
  assert.match(triage.mitre_tactic, /T1552/);
  assert.equal(triage.next_actions.length, 3);
  assert.ok(triage.confidence >= 90);
  assert.match(triage.next_actions[1], /OPENAI_API_KEY/);
});
