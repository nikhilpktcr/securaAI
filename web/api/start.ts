import { GUEST_USER, publicSession, sessionCookie } from "../lib/cookie-auth";
import { sendJson, withApi } from "../lib/vercel-handler";

export default withApi(async (req, res) => {
  if (req.method !== "POST") {
    return sendJson(res, 405, { error: "Method not allowed" });
  }

  const session = {
    user: { email: GUEST_USER.email, name: GUEST_USER.name },
    repo: null
  };

  return sendJson(
    res,
    200,
    { ok: true, free: true, ...publicSession(session) },
    { "Set-Cookie": sessionCookie(session) }
  );
});
