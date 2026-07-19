import { detectSecrets } from "./detectors";
import type { FindingResult, LinkedRepo, ScanResult } from "./types";

function isSupportedPath(filePath: string): boolean {
  return /\.(jsx?|tsx?)$/i.test(filePath);
}

export function parseGitHubRepo(input: string): { owner: string; name: string } {
  const value = String(input || "").trim().replace(/\.git$/i, "");

  let match = value.match(/^https?:\/\/github\.com\/([^/]+)\/([^/]+)\/?$/i);
  if (!match) {
    match = value.match(/^git@github\.com:([^/]+)\/([^/]+)$/i);
  }
  if (!match) {
    match = value.match(/^([^/]+)\/([^/]+)$/);
  }
  if (!match) {
    throw new Error("Use a GitHub repo URL like https://github.com/owner/repo");
  }

  return { owner: match[1], name: match[2].replace(/\.git$/i, "") };
}

async function githubFetch<T>(url: string, token?: string): Promise<T> {
  const headers: Record<string, string> = {
    Accept: "application/vnd.github+json",
    "User-Agent": "secura-ai-platform"
  };
  if (token) headers.Authorization = `Bearer ${token}`;

  const response = await fetch(url, { headers });
  if (!response.ok) {
    const text = await response.text();
    throw new Error(`GitHub API error (${response.status}): ${text.slice(0, 180)}`);
  }
  return response.json() as Promise<T>;
}

function lineFromOffset(text: string, offset: number): { line: number; character: number } {
  const before = text.slice(0, offset);
  const line = before.split(/\r?\n/).length;
  const lastBreak = Math.max(before.lastIndexOf("\n"), before.lastIndexOf("\r"));
  const character = offset - (lastBreak + 1) + 1;
  return { line, character };
}

function scanText(filePath: string, text: string, gitStatus: string): FindingResult[] {
  return detectSecrets(text).map((finding) => {
    const pos = lineFromOffset(text, finding.start);
    return {
      provider: finding.provider,
      secretType: finding.secretType,
      severity: finding.severity,
      envVarName: finding.envVarName,
      message: finding.message,
      explanation: finding.explanation,
      filePath,
      line: pos.line,
      character: pos.character,
      gitStatus
    };
  });
}

async function listLatestChangedFiles(
  owner: string,
  name: string,
  token?: string
): Promise<{ sha: string; files: string[]; mode: string }> {
  const commits = await githubFetch<Array<{ sha: string }>>(
    `https://api.github.com/repos/${owner}/${name}/commits?per_page=1`,
    token
  );
  const sha = commits?.[0]?.sha;
  if (!sha) throw new Error("No commits found in this repository.");

  const commit = await githubFetch<{ files?: Array<{ filename: string }> }>(
    `https://api.github.com/repos/${owner}/${name}/commits/${sha}`,
    token
  );
  const files = (commit.files || [])
    .map((file) => file.filename)
    .filter((filePath) => isSupportedPath(filePath))
    .slice(0, 30);

  return { sha, files, mode: "latest-commit" };
}

async function listTreeSample(
  owner: string,
  name: string,
  token?: string
): Promise<{ sha: string; files: string[]; mode: string }> {
  const repo = await githubFetch<{ default_branch?: string }>(
    `https://api.github.com/repos/${owner}/${name}`,
    token
  );
  const branch = repo.default_branch || "main";
  const ref = await githubFetch<{ object?: { sha?: string } }>(
    `https://api.github.com/repos/${owner}/${name}/git/ref/heads/${branch}`,
    token
  );
  const commitSha = ref?.object?.sha;
  if (!commitSha) throw new Error("Unable to resolve default branch commit.");

  const commit = await githubFetch<{ tree?: { sha?: string } }>(
    `https://api.github.com/repos/${owner}/${name}/git/commits/${commitSha}`,
    token
  );
  const treeSha = commit?.tree?.sha;
  if (!treeSha) throw new Error("Unable to resolve repository tree.");

  const tree = await githubFetch<{ tree?: Array<{ type?: string; path?: string }> }>(
    `https://api.github.com/repos/${owner}/${name}/git/trees/${treeSha}?recursive=1`,
    token
  );

  const files = (tree.tree || [])
    .filter((item) => item.type === "blob" && item.path && isSupportedPath(item.path))
    .slice(0, 30)
    .map((item) => item.path as string);

  return { sha: commitSha, files, mode: "workspace-sample" };
}

async function fetchFileText(owner: string, name: string, filePath: string, token?: string): Promise<string> {
  const encoded = filePath
    .split("/")
    .map((part) => encodeURIComponent(part))
    .join("/");
  const data = await githubFetch<{ encoding?: string; content?: string; download_url?: string }>(
    `https://api.github.com/repos/${owner}/${name}/contents/${encoded}`,
    token
  );

  if (data.encoding === "base64" && data.content) {
    return Buffer.from(data.content.replace(/\n/g, ""), "base64").toString("utf8");
  }
  if (data.download_url) {
    const resp = await fetch(data.download_url, {
      headers: { "User-Agent": "secura-ai-platform" }
    });
    if (!resp.ok) throw new Error(`Failed to download ${filePath}`);
    return resp.text();
  }
  throw new Error(`Unable to read ${filePath}`);
}

export async function scanGitHubRepo(
  repo: Pick<LinkedRepo, "owner" | "name">,
  token = process.env.GITHUB_TOKEN
): Promise<ScanResult> {
  const owner = repo.owner;
  const name = repo.name;
  if (!owner || !name) {
    throw new Error("Linked repository is missing owner/name.");
  }

  let target: { sha: string; files: string[]; mode: string };
  try {
    target = await listLatestChangedFiles(owner, name, token);
    if (!target.files.length) {
      target = await listTreeSample(owner, name, token);
    }
  } catch {
    target = await listTreeSample(owner, name, token);
  }

  const findings: FindingResult[] = [];
  const scannedFiles: Array<{ status: string; path: string }> = [];

  for (const filePath of target.files) {
    const status = target.mode === "latest-commit" ? "COMMIT" : "TREE";
    scannedFiles.push({ status, path: filePath });
    try {
      const text = await fetchFileText(owner, name, filePath, token);
      findings.push(...scanText(filePath, text, status));
    } catch {
      // Skip unreadable files.
    }
  }

  return {
    mode: target.mode,
    commitSha: target.sha,
    scannedFiles,
    findings,
    stats: {
      open: findings.length,
      scanned: scannedFiles.length,
      score: Math.max(0, 100 - findings.length * 20)
    },
    scannedAt: new Date().toISOString()
  };
}
