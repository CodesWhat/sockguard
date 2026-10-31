import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";

test("generated-file inventory ignores an inherited Git index", (t) => {
  const fixture = mkdtempSync(join(tmpdir(), "sockguard-git-index-"));
  t.after(() => rmSync(fixture, { recursive: true, force: true }));
  const env = { ...process.env, GIT_INDEX_FILE: join(fixture, "empty-index") };
  delete env.NODE_TEST_CONTEXT;
  const result = spawnSync(
    process.execPath,
    [
      "--test",
      "--test-name-pattern=Gosec scans canonical app packages with audited suppressions",
      "scripts/go-module-layout.test.mjs",
    ],
    { cwd: resolve(import.meta.dirname, ".."), env, encoding: "utf8", timeout: 20_000 },
  );
  assert.equal(result.status, 0, result.stdout + result.stderr);
  assert.match(result.stdout, /pass 1/);
});
