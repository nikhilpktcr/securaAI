import { clearCookie } from "../lib/cookie-auth";
import { sendJson, withApi } from "../lib/vercel-handler";

export default withApi(async (req, res) => {
  if (req.method !== "POST") {
    return sendJson(res, 405, { error: "Method not allowed" });
  }

  return sendJson(res, 200, { ok: true }, { "Set-Cookie": clearCookie() });
});
