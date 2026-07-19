const test = require("node:test");
const assert = require("node:assert/strict");
const { buildRemediationPlan, applyLine } = require("../out/remediationPlan.js");

function createFinding(overrides = {}) {
  return {
    provider: "openai",
    secretType: "OpenAI API key",
    severity: "critical",
    envVarName: "OPENAI_API_KEY",
    value: "sk-abcdef123456",
    start: 10,
    end: 24,
    message: "demo",
    explanation: "demo",
    document: { fileName: "demo/app.js" },
    range: {}
  };
}

test("builds preview and gitignore update when .env is missing", () => {
  const plan = buildRemediationPlan(createFinding(), "", "", "");
  assert.equal(plan.sourceReplacement, "process.env.OPENAI_API_KEY");
  assert.equal(plan.willAddEnvToGitignore, true);
  assert.equal(plan.conflictReason, undefined);
  assert.match(plan.preview, /Update \.gitignore: add \.env/);
});

test("flags conflicts for existing env var with different value", () => {
  const plan = buildRemediationPlan(
    createFinding(),
    "OPENAI_API_KEY=sk-existing\n",
    "OPENAI_API_KEY=\n",
    ".env\n"
  );
  assert.match(plan.conflictReason ?? "", /existing OPENAI_API_KEY/i);
  assert.equal(plan.willAddEnvToGitignore, false);
});

test("append helper keeps file idempotent", () => {
  assert.equal(applyLine("A=1\n", "A=1"), "A=1\n");
  assert.equal(applyLine("", ".env"), ".env\n");
});
