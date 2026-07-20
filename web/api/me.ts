import { GUEST_USER, publicSession, readSession, sessionCookie } from "../lib/cookie-auth";
import { sendJson, withApi } from "../lib/vercel-handler";

export default withApi(async (req, res) => {
  if (req.method !== "GET") {
    return sendJson(res, 405, { error: "Method not allowed" });
  }

  const existing = readSession(req);
  if (existing) {
    return sendJson(res, 200, publicSession(existing));
  }

  // Auto-start a free guest session so the product is usable without login.
  const session = {
    user: { email: GUEST_USER.email, name: GUEST_USER.name },
    repo: null
  };

  return sendJson(res, 200, { free: true, ...publicSession(session) }, {
    "Set-Cookie": sessionCookie(session)
  });
});
