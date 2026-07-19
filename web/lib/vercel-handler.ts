import type { VercelRequest, VercelResponse } from "@vercel/node";

export function sendJson(
  res: VercelResponse,
  status: number,
  data: unknown,
  extraHeaders: Record<string, string | undefined> = {}
): void {
  Object.entries(extraHeaders).forEach(([key, value]) => {
    if (value !== undefined) res.setHeader(key, value);
  });
  res.status(status).json(data);
}

export async function readJson<T extends Record<string, unknown> = Record<string, unknown>>(
  req: VercelRequest
): Promise<T> {
  if (req.body && typeof req.body === "object") {
    return req.body as T;
  }

  const chunks: Buffer[] = [];
  for await (const chunk of req) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  const raw = Buffer.concat(chunks).toString("utf8");
  if (!raw) return {} as T;
  return JSON.parse(raw) as T;
}

function allowCors(res: VercelResponse): void {
  res.setHeader("Access-Control-Allow-Credentials", "true");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
}

export function withApi(
  handler: (req: VercelRequest, res: VercelResponse) => Promise<void>
): (req: VercelRequest, res: VercelResponse) => Promise<void> {
  return async (req, res) => {
    allowCors(res);
    if (req.method === "OPTIONS") {
      res.status(204).end();
      return;
    }

    try {
      await handler(req, res);
    } catch (error) {
      const message = error instanceof Error ? error.message : "Unexpected server error.";
      sendJson(res, 500, { error: message });
    }
  };
}
