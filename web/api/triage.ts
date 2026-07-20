import { readSession } from "../lib/cookie-auth";
import { triageFinding, type TriageFinding } from "../lib/triage";
import { readJson, sendJson, withApi } from "../lib/vercel-handler";

export default withApi(async (req, res) => {
  if (req.method !== "POST") {
    return sendJson(res, 405, { error: "Method not allowed" });
  }

  const session = readSession(req);
  if (!session) {
    return sendJson(res, 401, { error: "Not authenticated." });
  }

  const body = await readJson<{ finding?: TriageFinding }>(req);
  if (!body.finding) {
    return sendJson(res, 400, { error: "finding is required." });
  }

  const result = await triageFinding(body.finding);
  return sendJson(res, 200, { ok: true, ...result });
});
