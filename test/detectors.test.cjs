const test = require("node:test");
const assert = require("node:assert/strict");
const { detectSecrets, isSupportedScanPath } = require("../out/detectors.js");

test("detects multiple high-signal secret types", () => {
  const code = `
    const openai = "sk-abcdefghijklmnopqrstuv";
    const anthropic = "sk-ant-abcdefghijklmnopqrstuv";
    const github = "ghp_abcdefghijklmnopqrstuvwxyz123456";
    const aws = "AKIA1234567890ABCD12";
    const awsSecret = { aws_secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" };
    const stripe = "sk_live_abcdefghijklmnopqrstuv";
    const slack = "xoxb-1234567890-abcdefghij";
    const google = "AIza01234567890123456789012345678901234";
    const password = "superSecret123";
  `;

  const findings = detectSecrets(code);
  const providers = findings.map((item) => item.provider);
  const types = findings.map((item) => item.secretType);

  assert.ok(providers.includes("openai"));
  assert.ok(providers.includes("anthropic"));
  assert.ok(providers.includes("github"));
  assert.ok(providers.includes("aws"));
  assert.ok(providers.includes("stripe"));
  assert.ok(providers.includes("slack"));
  assert.ok(providers.includes("google"));
  assert.ok(providers.includes("generic"));
  assert.ok(types.includes("AWS secret access key"));
  assert.equal(findings.find((f) => f.provider === "openai").envVarName, "OPENAI_API_KEY");
});

test("detects private key blocks", () => {
  const findings = detectSecrets("-----BEGIN RSA PRIVATE KEY-----\\nMIIE...");
  assert.equal(findings.length, 1);
  assert.equal(findings[0].secretType, "Private key material");
});

test("redacts values in explanations", () => {
  const findings = detectSecrets(`const key = "sk-abcdefghijklmnopqrstuv";`);
  assert.equal(findings.length, 1);
  assert.match(findings[0].explanation, /Detected value: sk-a\.\.\.uv/);
  assert.doesNotMatch(findings[0].explanation, /sk-abcdefghijklmnopqrstuv/);
});

test("supports common source and config extensions for free scans", () => {
  assert.equal(isSupportedScanPath("src/app.py"), true);
  assert.equal(isSupportedScanPath("infra/main.tf"), true);
  assert.equal(isSupportedScanPath("config/.env"), true);
  assert.equal(isSupportedScanPath("readme.md"), false);
});
