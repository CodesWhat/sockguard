import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { after, before, test } from "node:test";
import { fileURLToPath } from "node:url";

const SCRIPT = readFileSync(
  fileURLToPath(new URL("../website/scripts/vercel-ignore-build.sh", import.meta.url)),
  "utf8",
);

const SCRIPT_REL = "website/scripts/vercel-ignore-build.sh";

const FILES = [
  "website/src/page.tsx",
  SCRIPT_REL,
  "docs/content/index.mdx",
  "app/main.go",
  "package.json",
  "package-lock.json",
  "turbo.json",
  "biome.json",
  "scripts/analytics-routes.mjs",
  "scripts/analytics-runtime.mjs",
  ".vercelignore",
  "README.md",
];

let repo;
let base;

// Git hooks export GIT_DIR, GIT_INDEX_FILE and friends. When this runs from
// the pre-push hook, an inherited GIT_* variable would point every command
// below at the host repository instead of the temp repo, so drop them all.
const gitEnv = Object.fromEntries(
  Object.entries(process.env).filter(([k]) => !k.startsWith("GIT_")),
);
// Identity and signing go on the command line so nothing writes git config.
const gitConfig = [
  "-c",
  "user.email=t@example.com",
  "-c",
  "user.name=t",
  "-c",
  "commit.gpgsign=false",
];

function git(...args) {
  const res = spawnSync("git", [...gitConfig, ...args], {
    cwd: repo,
    encoding: "utf8",
    env: gitEnv,
  });
  assert.equal(res.status, 0, `git ${args.join(" ")}: ${res.stderr}`);
  return res.stdout.trim();
}

function write(rel, content) {
  const target = join(repo, rel);
  mkdirSync(dirname(target), { recursive: true });
  writeFileSync(target, content);
}

function commitChange(rel) {
  git("reset", "-q", "--hard", base);
  write(rel, `changed ${rel}\n`);
  git("add", "-A");
  git("commit", "-q", "-m", `change ${rel}`);
  return git("rev-parse", "HEAD");
}

function run(env) {
  const clean = { PATH: process.env.PATH, HOME: process.env.HOME };
  return spawnSync("bash", [join(repo, SCRIPT_REL)], {
    cwd: join(repo, "website"),
    env: { ...clean, ...env },
    encoding: "utf8",
  });
}

function previewEnv(head) {
  return { VERCEL_ENV: "preview", VERCEL_GIT_PREVIOUS_SHA: base, VERCEL_GIT_COMMIT_SHA: head };
}

before(() => {
  repo = mkdtempSync(join(tmpdir(), "vercel-ignore-"));
  git("init", "-q", "-b", "main");
  for (const f of FILES) write(f, f === SCRIPT_REL ? SCRIPT : `${f}\n`);
  git("add", "-A");
  git("commit", "-q", "-m", "base");
  base = git("rev-parse", "HEAD");
});

after(() => {
  rmSync(repo, { recursive: true, force: true });
});

test("production always builds", () => {
  const head = commitChange("app/main.go");
  const res = run({ ...previewEnv(head), VERCEL_ENV: "production" });
  assert.equal(res.status, 1, res.stdout + res.stderr);
});

test("empty previous SHA builds", () => {
  const res = run({ VERCEL_ENV: "preview", VERCEL_GIT_COMMIT_SHA: base });
  assert.equal(res.status, 1, res.stdout + res.stderr);
});

test("unknown previous SHA builds", () => {
  const res = run({
    VERCEL_ENV: "preview",
    VERCEL_GIT_PREVIOUS_SHA: "0123456789abcdef0123456789abcdef01234567",
    VERCEL_GIT_COMMIT_SHA: base,
  });
  assert.equal(res.status, 1, res.stdout + res.stderr);
});

for (const file of ["app/main.go", "README.md"]) {
  test(`a ${file} change skips`, () => {
    const res = run(previewEnv(commitChange(file)));
    assert.equal(res.status, 0, res.stdout + res.stderr);
    assert.match(res.stdout, /skipping/);
  });
}

for (const file of [
  "docs/content/index.mdx",
  "website/src/page.tsx",
  "package-lock.json",
  "package.json",
  "turbo.json",
  "biome.json",
  "scripts/analytics-routes.mjs",
  "scripts/analytics-runtime.mjs",
  ".vercelignore",
]) {
  test(`a ${file} change builds`, () => {
    const res = run(previewEnv(commitChange(file)));
    assert.equal(res.status, 1, res.stdout + res.stderr);
    assert.match(res.stdout, /building/);
  });
}
