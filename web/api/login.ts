import { DEMO_USER, GUEST_USER, publicSession, sessionCookie } from "../lib/cookie-auth";
import { readJson, sendJson, withApi } from "../lib/vercel-handler";

type LoginBody = {
  email?: string;
  password?: string;
  free?: boolean;
};

export default withApi(async (req, res) => {
  if (req.method !== "POST") {
    return sendJson(res, 405, { error: "Method not allowed" });
  }

  const body = await readJson<LoginBody>(req);

  // Free access path — no credentials required.
  if (body.free === true || (!body.email && !body.password)) {
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
  }

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
