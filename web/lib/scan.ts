import { execFile } from "child_process";
import fs from "fs";
import os from "os";
import path from "path";
import { promisify } from "util";
import { detectSecrets, isSupportedScanPath } from "./detectors";
import type { FindingResult, ScanResult } from "./types";

const execFileAsync = promisify(execFile);

function isSupportedPath(filePath: string): boolean {
  return isSupportedScanPath(filePath);
}

function parsePorcelainZ(stdout: string): Array<{ status: string; path: string }> {
  const entries = stdout.split("\0").filter(Boolean);
  const paths: Array<{ status: string; path: string }> = [];

  for (let index = 0; index < entries.length; index += 1) {
    const entry = entries[index];
    if (entry.length < 4) continue;
    const status = entry.slice(0, 2);
    let filePath = entry.slice(3);

    if (status.includes("R") || status.includes("C")) {
      const destination = entries[index + 1];
      if (destination) {
        filePath = destination;
        index += 1;
      }
    }

    const normalized = filePath.replace(/\\/g, "/").trim();
    if (normalized && isSupportedPath(normalized)) {
      paths.push({ status: status.trim(), path: normalized });
    }
  }

  return paths;
}

async function getGitRoot(startPath: string): Promise<string> {
  const { stdout } = await execFileAsync("git", ["rev-parse", "--show-toplevel"], {
    cwd: startPath
  });
  return stdout.trim();
}

async function getModifiedFiles(repoPath: string): Promise<{
  gitRoot: string;
  files: Array<{ status: string; path: string }>;
}> {
  const gitRoot = await getGitRoot(repoPath);
  const { stdout } = await execFileAsync(
    "git",
    ["status", "--porcelain", "-z", "--untracked-files=all"],
    { cwd: gitRoot }
  );
  return { gitRoot, files: parsePorcelainZ(stdout) };
}

function lineFromOffset(text: string, offset: number): { line: number; character: number } {
  const before = text.slice(0, offset);
  const line = before.split(/\r?\n/).length;
  const lastBreak = Math.max(before.lastIndexOf("\n"), before.lastIndexOf("\r"));
  const character = offset - (lastBreak + 1) + 1;
  return { line, character };
}

function scanFile(gitRoot: string, relativePath: string): FindingResult[] {
  const absolutePath = path.join(gitRoot, relativePath);
  if (!fs.existsSync(absolutePath)) return [];

  const text = fs.readFileSync(absolutePath, "utf8");
  return detectSecrets(text).map((finding) => {
    const pos = lineFromOffset(text, finding.start);
    return {
      provider: finding.provider,
      secretType: finding.secretType,
      severity: finding.severity,
      envVarName: finding.envVarName,
      message: finding.message,
      explanation: finding.explanation,
      filePath: relativePath,
      absolutePath,
      line: pos.line,
      character: pos.character
    };
  });
}

function walkSupportedFiles(
  rootDir: string,
  relativeDir = "",
  collected: Array<{ status: string; path: string }> = []
): Array<{ status: string; path: string }> {
  const absDir = path.join(rootDir, relativeDir);
  const entries = fs.readdirSync(absDir, { withFileTypes: true });

  for (const entry of entries) {
    if (entry.name === "node_modules" || entry.name === ".git" || entry.name === "out" || entry.name === "web") {
      continue;
    }
    const rel = relativeDir ? `${relativeDir}/${entry.name}` : entry.name;
    if (entry.isDirectory()) {
      walkSupportedFiles(rootDir, rel, collected);
      continue;
    }
    if (isSupportedPath(rel)) {
      collected.push({ status: "TREE", path: rel.replace(/\\/g, "/") });
    }
    if (collected.length >= 100) break;
  }

  return collected;
}

async function getScanTargets(repoPath: string): Promise<{
  gitRoot: string;
  files: Array<{ status: string; path: string }>;
  mode: string;
}> {
  const { gitRoot, files } = await getModifiedFiles(repoPath);
  if (files.length > 0) {
    return { gitRoot, files, mode: "modified" };
  }

  try {
    const { stdout } = await execFileAsync("git", ["diff", "--name-only", "--diff-filter=ACMR", "HEAD~1", "HEAD"], {
      cwd: gitRoot
    });
    const recent = stdout
      .split(/\r?\n/)
      .map((item) => item.trim())
      .filter((item) => item && isSupportedPath(item))
      .map((item) => ({ status: "COMMIT", path: item }));
    if (recent.length > 0) {
      return { gitRoot, files: recent, mode: "latest-commit" };
    }
  } catch {
    // Single-commit clones may not have HEAD~1.
  }

  return { gitRoot, files: walkSupportedFiles(gitRoot), mode: "workspace-sample" };
}

export async function scanModifiedFiles(repoPath: string): Promise<ScanResult> {
  const { gitRoot, files, mode } = await getScanTargets(repoPath);
  const findings: FindingResult[] = [];
  const scanned: Array<{ status: string; path: string }> = [];

  for (const file of files) {
    scanned.push(file);
    findings.push(...scanFile(gitRoot, file.path).map((item) => ({ ...item, gitStatus: file.status })));
  }

  return {
    gitRoot,
    mode,
    scannedFiles: scanned,
    findings,
    stats: {
      open: findings.length,
      scanned: scanned.length,
      score: Math.max(0, 100 - findings.length * 20)
    },
    scannedAt: new Date().toISOString()
  };
}

export function normalizeRepoInput(input: string): { type: "remote"; url: string } | { type: "local"; path: string } {
  const value = String(input || "").trim();
  if (!value) throw new Error("Repository path or GitHub URL is required.");

  if (value.startsWith("http://") || value.startsWith("https://") || value.startsWith("git@")) {
    return { type: "remote", url: value };
  }

  const resolved = path.resolve(value);
  if (!fs.existsSync(resolved)) {
    throw new Error(`Local path not found: ${resolved}`);
  }
  return { type: "local", path: resolved };
}

export async function ensureRemoteRepo(url: string, cacheDir: string): Promise<string> {
  // Vercel serverless FS is read-only (except /tmp). Never clone into the deploy bundle.
  if (process.env.VERCEL) {
    throw new Error(
      "Git clone is not available on Vercel. Link a public GitHub URL and use the GitHub API scan path."
    );
  }

  // Prefer an explicit writable cache; never mkdir inside the app bundle.
  const resolvedCache = cacheDir.startsWith(os.tmpdir())
    ? cacheDir
    : path.join(os.tmpdir(), "secura-repos");

  fs.mkdirSync(resolvedCache, { recursive: true });
  const slug = url
    .replace(/\.git$/i, "")
    .split("/")
    .filter(Boolean)
    .slice(-2)
    .join("-")
    .replace(/[^\w.-]+/g, "_");
  const target = path.join(resolvedCache, slug || "repo");

  if (fs.existsSync(path.join(target, ".git"))) {
    try {
      await execFileAsync("git", ["fetch", "--depth", "1", "origin"], { cwd: target });
      await execFileAsync("git", ["checkout", "FETCH_HEAD"], { cwd: target });
    } catch {
      // Keep existing clone if fetch fails.
    }
    return target;
  }

  await execFileAsync("git", ["clone", "--depth", "1", url, target]);
  return target;
}
