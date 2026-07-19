import { publicSession, readSession, sessionCookie } from "../lib/cookie-auth";
import { parseGitHubRepo } from "../lib/github";
import { readJson, sendJson, withApi } from "../lib/vercel-handler";

type LinkBody = {
  repo?: string;
};

export default withApi(async (req, res) => {
  if (req.method !== "POST") {
    return sendJson(res, 405, { error: "Method not allowed" });
  }

  const current = readSession(req);
  if (!current) {
    return sendJson(res, 401, { error: "Not authenticated." });
  }

  const body = await readJson<LinkBody>(req);
  const input = String(body.repo || "").trim();
  const parsed = parseGitHubRepo(input);

  const session = {
    user: current.user,
    repo: {
      input,
      owner: parsed.owner,
      name: parsed.name,
      source: "github" as const,
      linkedAt: new Date().toISOString()
    }
  };

  return sendJson(
    res,
    200,
    { ok: true, repo: session.repo, ...publicSession(session) },
    { "Set-Cookie": sessionCookie(session) }
  );
});
