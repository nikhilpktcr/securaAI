const test = require("node:test");
const assert = require("node:assert/strict");
const { detectSecrets } = require("../out/detectors.js");

test("detects multiple high-signal secret types", () => {
  const code = `
    const openai = "sk-demo1234567890abcdef";
    const github = "ghp_abcdefghijklmnopqrstuvwxyz123456";
    const aws = "AKIA1234567890ABCD12";
    const password = "superSecret123";
  `;

  const findings = detectSecrets(code);
  const providers = findings.map(item => item.provider);

  assert.deepEqual(providers, ["openai", "github", "aws", "generic"]);
  assert.equal(findings[0].envVarName, "OPENAI_API_KEY");
  assert.equal(findings[1].envVarName, "GITHUB_TOKEN");
  assert.equal(findings[2].envVarName, "AWS_ACCESS_KEY_ID");
  assert.equal(findings[3].envVarName, "APP_PASSWORD");
});

test("redacts values in explanations", () => {
  const findings = detectSecrets(`const key = "sk-abcdef1234567890";`);
  assert.equal(findings.length, 1);
  assert.match(findings[0].explanation, /Detected value: sk-a\.\.\.90/);
  assert.doesNotMatch(findings[0].explanation, /sk-abcdef1234567890/);
});
