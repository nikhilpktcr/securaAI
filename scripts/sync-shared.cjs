#!/usr/bin/env node
/**
 * Copies shared/*.ts into extension + web so both surfaces stay identical
 * without cross-package rootDir / Vercel layout pain.
 */
const fs = require("fs");
const path = require("path");

const root = path.join(__dirname, "..");
const sharedFile = path.join(root, "shared", "detectors.ts");
const targets = [
  path.join(root, "src", "detectors.ts"),
  path.join(root, "web", "lib", "detectors.ts")
];

const banner =
  "/* Generated from shared/detectors.ts — edit shared/detectors.ts, then run: node scripts/sync-shared.cjs */\n";

if (!fs.existsSync(sharedFile)) {
  console.error("Missing shared/detectors.ts");
  process.exit(1);
}

const body = fs.readFileSync(sharedFile, "utf8");
for (const target of targets) {
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, banner + body);
  console.log(`synced ${path.relative(root, target)}`);
}
