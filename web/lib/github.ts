import { detectSecrets, isSupportedScanPath } from "./detectors";
import type { FindingResult, LinkedRepo, ScanResult } from "./types";

function isSupportedPath(filePath: string): boolean {
  return isSupportedScanPath(filePath);
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

const MAX_SCAN_FILES = 100;
const RECENT_COMMIT_PAGES = 20;

async function listRecentChangedFiles(
  owner: string,
  name: string,
  token?: string
): Promise<{ sha: string; files: string[]; mode: string }> {
  const commits = await githubFetch<Array<{ sha: string }>>(
    `https://api.github.com/repos/${owner}/${name}/commits?per_page=${RECENT_COMMIT_PAGES}`,
    token
  );
  if (!commits?.length) throw new Error("No commits found in this repository.");

  const seen = new Set<string>();
  const files: string[] = [];

  for (const entry of commits) {
    if (files.length >= MAX_SCAN_FILES) break;
    const commit = await githubFetch<{ files?: Array<{ filename: string }> }>(
      `https://api.github.com/repos/${owner}/${name}/commits/${entry.sha}`,
      token
    );
    for (const file of commit.files || []) {
      if (!isSupportedPath(file.filename) || seen.has(file.filename)) continue;
      seen.add(file.filename);
      files.push(file.filename);
      if (files.length >= MAX_SCAN_FILES) break;
    }
  }

  return { sha: commits[0].sha, files, mode: "recent-commits" };
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
    .slice(0, MAX_SCAN_FILES)
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
    target = await listRecentChangedFiles(owner, name, token);
    // One-line tip commits (e.g. a single fix) are too narrow for a useful scan.
    if (target.files.length < 8) {
      const before = target.files.length;
      const sample = await listTreeSample(owner, name, token);
      const seen = new Set(target.files);
      for (const filePath of sample.files) {
        if (seen.has(filePath)) continue;
        target.files.push(filePath);
        seen.add(filePath);
        if (target.files.length >= MAX_SCAN_FILES) break;
      }
      if (before === 0) {
        target.mode = "workspace-sample";
      } else if (target.files.length > before) {
        target.mode = "recent+sample";
      }
      target.sha = sample.sha || target.sha;
    }
  } catch {
    target = await listTreeSample(owner, name, token);
  }

  const findings: FindingResult[] = [];
  const scannedFiles: Array<{ status: string; path: string }> = [];

  for (const filePath of target.files) {
    const status = target.mode === "workspace-sample" ? "TREE" : "COMMIT";
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
