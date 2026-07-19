const path = require("path");
const { spawn } = require("child_process");

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

  const raw = cliPort || process.env.PORT || "8789";
  const parsed = Number(raw);
  if (!Number.isInteger(parsed) || parsed < 1 || parsed > 65535) {
    return 8789;
  }
  return parsed;
}

const port = resolvePort();
const triageServerPath = path.join(__dirname, "triage-server.js");

console.log("Secura Insights");
console.log("Local scan summary for developers.");
console.log(`Detailed error: please go to http://localhost:${port}.`);
console.log("AI fluency triage: intent, grounded context, reasoning, MITRE, actions.");
console.log(`Starting triage app on http://localhost:${port} ...`);
console.log("");

const child = spawn(process.execPath, [triageServerPath, `--port=${port}`], {
  stdio: "inherit",
  env: process.env
});

function stopChild() {
  if (!child.killed) {
    child.kill("SIGINT");
  }
}

process.on("SIGINT", stopChild);
process.on("SIGTERM", stopChild);

child.on("exit", (code) => {
  process.exit(code ?? 0);
});
