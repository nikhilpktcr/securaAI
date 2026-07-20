/**
 * Extension smoke test — compile artifacts, demo scan, remediation plan, package metadata.
 * Run: node test/extension.smoke.cjs
 */
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { execFileSync } = require("node:child_process");

const root = path.join(__dirname, "..");
const outDir = path.join(root, "out");

test("extension compiles and exposes activate/deactivate", () => {
  const extensionJs = path.join(outDir, "extension.js");
  assert.ok(fs.existsSync(extensionJs), "out/extension.js missing — run npm run compile");

  const required = [
    "detectors.js",
    "scanner.js",
    "remediation.js",
    "remediationPlan.js",
    "dashboard.js",
    "stats.js",
    "types.js"
  ];
  for (const file of required) {
    assert.ok(fs.existsSync(path.join(outDir, file)), `missing out/${file}`);
  }

  // vscode is only available inside the Extension Host — don't require() the entry.
  const source = fs.readFileSync(extensionJs, "utf8");
  assert.match(source, /exports\.activate\s*=/);
  assert.match(source, /exports\.deactivate\s*=/);
  assert.match(source, /secura\.scanModifiedFiles/);
  assert.match(source, /secura\.fixSecret/);
});

test("package.json contributes Secura commands", () => {
  const pkg = JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf8"));
  assert.equal(pkg.main, "./out/extension.js");
  assert.ok(pkg.engines?.vscode);

  const titles = (pkg.contributes?.commands || []).map((c) => c.command);
  assert.ok(titles.includes("secura.scanModifiedFiles"));
  assert.ok(titles.includes("secura.fixSecret"));
  assert.ok(titles.includes("secura.openDashboard"));
  assert.ok(titles.includes("secura.openInsightsTerminal"));
});

test("smoke: detect secrets in demo/app.js", () => {
  const { detectSecrets } = require(path.join(outDir, "detectors.js"));
  const demo = fs.readFileSync(path.join(root, "demo", "app.js"), "utf8");
  const findings = detectSecrets(demo);

  assert.ok(findings.length >= 1, "expected at least one finding in demo/app.js");
  assert.equal(findings[0].provider, "openai");
  assert.equal(findings[0].envVarName, "OPENAI_API_KEY");
  assert.match(findings[0].explanation, /Detected value:/);
  assert.doesNotMatch(findings[0].explanation, /sk-demo-abcdefghijklmnopqrstuvwx/);
});

test("smoke: remediation plan for demo finding", () => {
  const { detectSecrets } = require(path.join(outDir, "detectors.js"));
  const { buildRemediationPlan } = require(path.join(outDir, "remediationPlan.js"));

  const demo = fs.readFileSync(path.join(root, "demo", "app.js"), "utf8");
  const [detection] = detectSecrets(demo);
  assert.ok(detection);

  // Minimal finding shape used by remediationPlan (document/range unused by plan builder).
  const finding = {
    ...detection,
    document: { uri: { fsPath: path.join(root, "demo", "app.js") } },
    range: { start: { line: 0, character: 0 }, end: { line: 0, character: 1 } }
  };

  const plan = buildRemediationPlan(finding, "", "", "");
  assert.ok(!plan.conflictReason, plan.conflictReason || "unexpected conflict");
  assert.match(plan.sourceReplacement, /process\.env\.OPENAI_API_KEY/);
  assert.match(plan.envLine, /OPENAI_API_KEY=/);
  assert.match(plan.exampleLine, /OPENAI_API_KEY=/);
  assert.equal(plan.willAddEnvToGitignore, true);
  assert.ok(plan.preview.length > 0);
});

test("smoke: package VSIX", () => {
  execFileSync("npm", ["run", "package"], {
    cwd: root,
    stdio: "pipe",
    shell: process.platform === "win32"
  });

  const vsix = fs
    .readdirSync(root)
    .filter((name) => name.endsWith(".vsix"))
    .map((name) => ({ name, mtime: fs.statSync(path.join(root, name)).mtimeMs }))
    .sort((a, b) => b.mtime - a.mtime)[0];

  assert.ok(vsix, "no .vsix produced");
  const size = fs.statSync(path.join(root, vsix.name)).size;
  assert.ok(size > 1000, `vsix too small: ${vsix.name} (${size} bytes)`);
  console.log(`  packaged ${vsix.name} (${Math.round(size / 1024)} KB)`);
});
