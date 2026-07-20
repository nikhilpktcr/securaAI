import crypto from "crypto";
import type { IncomingMessage } from "http";
import type { SessionPayload, SessionUser } from "./types";

const COOKIE = "secura_session";
const SECRET = process.env.SESSION_SECRET || "secura-demo-session-secret";
const MAX_AGE_SEC = 60 * 60 * 12;

/** Free public access — no password required. */
export const GUEST_USER = {
  email: "guest@secura.ai",
  name: "Free user"
};

function b64url(input: string): string {
  return Buffer.from(input)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function fromB64url(input: string): string {
  const padded = input + "=".repeat((4 - (input.length % 4)) % 4);
  return Buffer.from(padded.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8");
}

export function signPayload(payload: SessionPayload): string {
  const body = b64url(JSON.stringify(payload));
  const sig = crypto.createHmac("sha256", SECRET).update(body).digest("base64url");
  return `${body}.${sig}`;
}

export function verifyToken(token: string | undefined): SessionPayload | null {
  if (!token || !token.includes(".")) return null;
  const [body, sig] = token.split(".");
  const expected = crypto.createHmac("sha256", SECRET).update(body).digest("base64url");
  const left = Buffer.from(sig);
  const right = Buffer.from(expected);
  if (left.length !== right.length || !crypto.timingSafeEqual(left, right)) return null;

  try {
    const payload = JSON.parse(fromB64url(body)) as SessionPayload;
    if (!payload?.exp || Date.now() > payload.exp) return null;
    return payload;
  } catch {
    return null;
  }
}

function parseCookies(header: string | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  String(header || "")
    .split(";")
    .map((part) => part.trim())
    .filter(Boolean)
    .forEach((part) => {
      const idx = part.indexOf("=");
      if (idx === -1) return;
      out[part.slice(0, idx)] = decodeURIComponent(part.slice(idx + 1));
    });
  return out;
}

export function readSession(req: IncomingMessage): SessionPayload | null {
  const cookies = parseCookies(req.headers.cookie);
  return verifyToken(cookies[COOKIE]);
}

export function sessionCookie(payload: Omit<SessionPayload, "exp">): string {
  const token = signPayload({
    ...payload,
    exp: Date.now() + MAX_AGE_SEC * 1000
  });
  const secure = process.env.VERCEL ? "; Secure" : "";
  return `${COOKIE}=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${MAX_AGE_SEC}${secure}`;
}

export function clearCookie(): string {
  const secure = process.env.VERCEL ? "; Secure" : "";
  return `${COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0${secure}`;
}

export function publicSession(session: SessionPayload | null): {
  user: SessionUser;
  repo: SessionPayload["repo"];
} | null {
  if (!session) return null;
  return {
    user: session.user,
    repo: session.repo || null
  };
}
