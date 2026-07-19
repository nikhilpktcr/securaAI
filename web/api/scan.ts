import { readSession } from "../lib/cookie-auth";
import { scanGitHubRepo } from "../lib/github";
import { sendJson, withApi } from "../lib/vercel-handler";

export default withApi(async (req, res) => {
  if (req.method !== "POST") {
    return sendJson(res, 405, { error: "Method not allowed" });
  }

  const session = readSession(req);
  if (!session) {
    return sendJson(res, 401, { error: "Not authenticated." });
  }
  if (!session.repo?.owner || !session.repo?.name) {
    return sendJson(res, 400, { error: "Link a GitHub repository before scanning." });
  }

  const result = await scanGitHubRepo(session.repo, process.env.GITHUB_TOKEN);
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
});
