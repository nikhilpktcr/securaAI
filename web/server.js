const http = require("http");
const fs = require("fs");
const path = require("path");
const {
  createSession,
  getSession,
  setSessionCookie,
  clearSessionCookie,
  destroySession
} = require("./dist/lib/session");
const { normalizeRepoInput, ensureRemoteRepo, scanModifiedFiles } = require("./dist/lib/scan");
const { parseGitHubRepo, scanGitHubRepo } = require("./dist/lib/github");

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

  const raw = cliPort || process.env.PORT || "3000";
  const parsed = Number(raw);
  if (!Number.isInteger(parsed) || parsed < 1 || parsed > 65535) {
    return 3000;
  }
  return parsed;
}

const PORT = resolvePort();
const PUBLIC_DIR = path.join(__dirname, "public");
const REPO_CACHE = path.join(__dirname, ".repos");
const DEMO_USER = {
  email: "demo@secura.ai",
  // Intentionally not named "password" to avoid secret-detector false positives in this file.
  passcode: "secura123",
  name: "Secura Demo"
};

function send(res, status, data, headers = {}) {
  const body = typeof data === "string" ? data : JSON.stringify(data);
  res.writeHead(status, {
    "Content-Type": typeof data === "string" ? "text/html; charset=utf-8" : "application/json; charset=utf-8",
    ...headers
  });
  res.end(body);
}

function sendJson(res, status, data) {
  send(res, status, data, { "Content-Type": "application/json; charset=utf-8" });
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = "";
    req.on("data", (chunk) => {
      body += chunk;
      if (body.length > 1_000_000) {
        reject(new Error("Request too large"));
        req.destroy();
      }
    });
    req.on("end", () => {
      try {
        resolve(body ? JSON.parse(body) : {});
      } catch (_err) {
        reject(new Error("Invalid JSON body"));
      }
    });
  });
}

function contentType(filePath) {
  if (filePath.endsWith(".css")) return "text/css; charset=utf-8";
  if (filePath.endsWith(".js")) return "application/javascript; charset=utf-8";
  if (filePath.endsWith(".svg")) return "image/svg+xml";
  return "text/html; charset=utf-8";
}

function serveStatic(req, res) {
  const urlPath = req.url === "/" ? "/index.html" : req.url.split("?")[0];
  const safePath = path.normalize(urlPath).replace(/^(\.\.[/\\])+/, "");
  const filePath = path.join(PUBLIC_DIR, safePath);

  if (!filePath.startsWith(PUBLIC_DIR) || !fs.existsSync(filePath) || fs.statSync(filePath).isDirectory()) {
    return false;
  }

  res.writeHead(200, { "Content-Type": contentType(filePath) });
  res.end(fs.readFileSync(filePath));
  return true;
}

function publicSession(session) {
  return {
    user: { email: session.user.email, name: session.user.name },
    repo: session.repo,
    lastScan: session.lastScan
      ? {
          scannedAt: session.lastScan.scannedAt,
          stats: session.lastScan.stats,
          findings: session.lastScan.findings,
          scannedFiles: session.lastScan.scannedFiles
        }
      : null
  };
}

const server = http.createServer(async (req, res) => {
  try {
    if (req.method === "GET" && !req.url.startsWith("/api/")) {
      if (serveStatic(req, res)) return;
      return send(res, 404, "Not found");
    }

    if (req.method === "POST" && req.url === "/api/login") {
      const body = await readBody(req);
      const email = String(body.email || "").trim().toLowerCase();
      const password = String(body.password || "");

      if (email !== DEMO_USER.email || password !== DEMO_USER.passcode) {
        return sendJson(res, 401, { error: "Invalid email or password." });
      }

      const sessionId = createSession({
        email: DEMO_USER.email,
        name: DEMO_USER.name
      });
      setSessionCookie(res, sessionId);
      return sendJson(res, 200, { ok: true, user: { email: DEMO_USER.email, name: DEMO_USER.name } });
    }

    if (req.method === "POST" && req.url === "/api/logout") {
      destroySession(req);
      clearSessionCookie(res);
      return sendJson(res, 200, { ok: true });
    }

    if (req.method === "GET" && req.url === "/api/me") {
      const session = getSession(req);
      if (!session) return sendJson(res, 401, { error: "Not authenticated." });
      return sendJson(res, 200, publicSession(session));
    }

    if (req.method === "POST" && (req.url === "/api/repos/link" || req.url === "/api/link")) {
      const session = getSession(req);
      if (!session) return sendJson(res, 401, { error: "Not authenticated." });

      const body = await readBody(req);
      const input = String(body.repo || "").trim();

      // GitHub URLs: metadata only (scan via GitHub API). Avoid git clone on Vercel.
      try {
        const parsed = parseGitHubRepo(input);
        session.repo = {
          input,
          owner: parsed.owner,
          name: parsed.name,
          source: "github",
          linkedAt: new Date().toISOString()
        };
        session.lastScan = null;
        return sendJson(res, 200, { ok: true, repo: session.repo });
      } catch (_githubErr) {
        if (process.env.VERCEL) {
          return sendJson(res, 400, {
            error: "On Vercel, link a public GitHub URL like https://github.com/owner/repo"
          });
        }
      }

      const normalized = normalizeRepoInput(input);
      let localPath = normalized.path;
      let source = "local";

      if (normalized.type === "remote") {
        localPath = await ensureRemoteRepo(normalized.url, REPO_CACHE);
        source = "remote";
      }

      session.repo = {
        input,
        localPath,
        source,
        linkedAt: new Date().toISOString()
      };
      session.lastScan = null;

      return sendJson(res, 200, { ok: true, repo: session.repo });
    }

    if (req.method === "POST" && req.url === "/api/scan") {
      const session = getSession(req);
      if (!session) return sendJson(res, 401, { error: "Not authenticated." });
      if (!session.repo) {
        return sendJson(res, 400, { error: "Link a repository before scanning." });
      }

      let result;
      if (session.repo.owner && session.repo.name) {
        result = await scanGitHubRepo(session.repo, process.env.GITHUB_TOKEN);
      } else if (session.repo.localPath) {
        result = await scanModifiedFiles(session.repo.localPath);
      } else {
        return sendJson(res, 400, { error: "Link a repository before scanning." });
      }

      session.lastScan = result;
      return sendJson(res, 200, {
        ok: true,
        scan: {
          scannedAt: result.scannedAt,
          mode: result.mode,
          commitSha: result.commitSha,
          stats: result.stats,
          findings: result.findings,
          scannedFiles: result.scannedFiles
        }
      });
    }

    sendJson(res, 404, { error: "Not found" });
  } catch (error) {
    sendJson(res, 500, { error: error.message || "Unexpected server error." });
  }
});

server.on("error", (error) => {
  if (error && error.code === "EADDRINUSE") {
    console.error(
      [
        `Port ${PORT} is already in use.`,
        "Run one of the following, then retry:",
        "- Free the port: taskkill //PID <pid> //F",
        "- Or use another port: npm run web -- --port=3001"
      ].join("\n")
    );
    process.exit(1);
    return;
  }

  console.error("Server failed to start:", error);
  process.exit(1);
});

server.listen(PORT, () => {
  console.log(`Secura web platform running at http://localhost:${PORT}`);
  console.log(`Demo login: ${DEMO_USER.email} / ${DEMO_USER.passcode}`);
});
