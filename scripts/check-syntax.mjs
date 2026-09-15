#!/usr/bin/env node
/**
 * scripts/check-syntax.mjs
 *
 * Walks this project's own source directories (server/, tests/, scripts/) and
 * runs `node --check <file>` against every .js/.mjs file found, without
 * executing any of them. Prints which file(s) failed and exits non-zero on
 * the first syntax error batch found (after checking all files, so a single
 * run reports every broken file, not just the first).
 *
 * Deliberately simple: shells out to `node --check` per file via
 * child_process, rather than reimplementing a JS parser. This is reliable
 * (uses the same parser Node itself will use to run the file) and needs no
 * extra dependency.
 */

import { readdir } from "node:fs/promises";
import { join, relative, extname } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";

const __filename = fileURLToPath(import.meta.url);
const projectRoot = join(__filename, "..", "..");

const SCAN_DIRS = ["cloud-functions", "server", "tests", "scripts"];
const EXTENSIONS = new Set([".js", ".mjs"]);
const SKIP_DIR_NAMES = new Set(["node_modules", ".git"]);

/**
 * Recursively collect all files with a matching extension under `dir`.
 * @param {string} dir
 * @returns {Promise<string[]>}
 */
async function collectFiles(dir) {
  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch (err) {
    if (err && err.code === "ENOENT") return [];
    throw err;
  }

  const files = [];
  for (const entry of entries) {
    if (SKIP_DIR_NAMES.has(entry.name)) continue;
    const fullPath = join(dir, entry.name);
    if (entry.isDirectory()) {
      files.push(...(await collectFiles(fullPath)));
    } else if (entry.isFile() && EXTENSIONS.has(extname(entry.name))) {
      files.push(fullPath);
    }
  }
  return files;
}

/**
 * Run `node --check <file>` and resolve with { ok, stderr }.
 * @param {string} filePath
 * @returns {Promise<{ ok: boolean, stderr: string }>}
 */
function checkFile(filePath) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, ["--check", filePath], {
      stdio: ["ignore", "ignore", "pipe"],
    });
    let stderr = "";
    child.stderr.on("data", (chunk) => {
      stderr += chunk.toString("utf8");
    });
    child.on("close", (code) => {
      resolve({ ok: code === 0, stderr });
    });
    child.on("error", (err) => {
      resolve({ ok: false, stderr: String(err && err.message ? err.message : err) });
    });
  });
}

async function main() {
  const allFiles = [];
  for (const dir of SCAN_DIRS) {
    const files = await collectFiles(join(projectRoot, dir));
    allFiles.push(...files);
  }

  if (allFiles.length === 0) {
    console.log("check-syntax: no .js/.mjs files found under server/, tests/, scripts/ — nothing to check.");
    return;
  }

  const results = await Promise.all(
    allFiles.map(async (filePath) => ({
      filePath,
      ...(await checkFile(filePath)),
    }))
  );

  const failures = results.filter((r) => !r.ok);

  for (const r of results) {
    const relPath = relative(projectRoot, r.filePath);
    console.log(`${r.ok ? "OK  " : "FAIL"}  ${relPath}`);
  }

  if (failures.length > 0) {
    console.error(`\ncheck-syntax: ${failures.length} of ${results.length} file(s) failed syntax check:\n`);
    for (const f of failures) {
      console.error(`--- ${relative(projectRoot, f.filePath)} ---`);
      console.error(f.stderr.trim());
      console.error("");
    }
    process.exitCode = 1;
    return;
  }

  console.log(`\ncheck-syntax: all ${results.length} file(s) passed syntax check.`);
}

main().catch((err) => {
  console.error("check-syntax: unexpected error while running syntax check:");
  console.error(err);
  process.exitCode = 1;
});
