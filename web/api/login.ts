import { DEMO_USER, publicSession, sessionCookie } from "../lib/cookie-auth";
import { readJson, sendJson, withApi } from "../lib/vercel-handler";

type LoginBody = {
  email?: string;
  password?: string;
};

export default withApi(async (req, res) => {
  if (req.method !== "POST") {
    return sendJson(res, 405, { error: "Method not allowed" });
  }

  const body = await readJson<LoginBody>(req);
  const email = String(body.email || "").trim().toLowerCase();
  const password = String(body.password || "");

  if (email !== DEMO_USER.email || password !== DEMO_USER.passcode) {
    return sendJson(res, 401, { error: "Invalid email or password." });
  }

  const session = {
    user: { email: DEMO_USER.email, name: DEMO_USER.name },
    repo: null
  };

  return sendJson(
    res,
    200,
    { ok: true, ...publicSession(session) },
    { "Set-Cookie": sessionCookie(session) }
  );
});
