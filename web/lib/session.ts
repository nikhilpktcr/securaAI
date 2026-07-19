import crypto from "crypto";
import type { IncomingMessage, ServerResponse } from "http";
import type { LinkedRepo, ScanResult, SessionUser } from "./types";

const sessions = new Map<string, MemorySession>();
const COOKIE = "secura_session";
const MAX_AGE_MS = 1000 * 60 * 60 * 12;

export type MemorySession = {
  id: string;
  user: SessionUser;
  repo: LinkedRepo | null;
  lastScan: ScanResult | null;
  createdAt: number;
};

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

export function createSession(user: SessionUser): string {
  const id = crypto.randomBytes(24).toString("hex");
  sessions.set(id, {
    id,
    user,
    repo: null,
    lastScan: null,
    createdAt: Date.now()
  });
  return id;
}

export function getSession(req: IncomingMessage): MemorySession | null {
  const cookies = parseCookies(req.headers.cookie);
  const id = cookies[COOKIE];
  if (!id) return null;
  const session = sessions.get(id);
  if (!session) return null;
  if (Date.now() - session.createdAt > MAX_AGE_MS) {
    sessions.delete(id);
    return null;
  }
  return session;
}

export function setSessionCookie(res: ServerResponse, sessionId: string): void {
  res.setHeader(
    "Set-Cookie",
    `${COOKIE}=${encodeURIComponent(sessionId)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${Math.floor(MAX_AGE_MS / 1000)}`
  );
}

export function clearSessionCookie(res: ServerResponse): void {
  res.setHeader("Set-Cookie", `${COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`);
}

export function destroySession(req: IncomingMessage): void {
  const cookies = parseCookies(req.headers.cookie);
  const id = cookies[COOKIE];
  if (id) sessions.delete(id);
}
