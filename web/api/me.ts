import { publicSession, readSession } from "../lib/cookie-auth";
import { sendJson, withApi } from "../lib/vercel-handler";

export default withApi(async (req, res) => {
  if (req.method !== "GET") {
    return sendJson(res, 405, { error: "Method not allowed" });
  }

  const session = readSession(req);
  if (!session) {
    return sendJson(res, 401, { error: "Not authenticated." });
  }

  return sendJson(res, 200, publicSession(session));
});
