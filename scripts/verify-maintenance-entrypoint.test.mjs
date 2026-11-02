import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { copyFileSync, mkdtempSync, rmSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

test("maintenance CLI checks spaced and symlinked entrypoint paths", () => {
  const fixture = mkdtempSync(join(tmpdir(), "sockguard maintenance "));
  try {
    for (const file of [
      "verify-maintenance-line.mjs",
      "verify-tag-release-metadata.mjs",
      "chart-image-tag.mjs",
      "extract-changelog-entry.mjs",
    ]) {
      copyFileSync(new URL(file, import.meta.url), join(fixture, file));
    }
    const script = join(fixture, "verify-maintenance-line.mjs");
    const link = join(fixture, "maintenance-link.mjs");
    symlinkSync(script, link);
    for (const entrypoint of [script, link]) {
      for (const [supported, expected] of [
        [true, 0],
        [false, 1],
      ]) {
        const result = spawnSync(process.execPath, [entrypoint, "v2.4.2"], {
          input: `| Version | Supported |\n| --- | --- |\n| 3.0.x | :white_check_mark: |\n| 2.4.x | ${supported ? ":white_check_mark:" : ":x:"} |\n`,
          encoding: "utf8",
          timeout: 5000,
        });
        assert.equal(result.status, expected, `${entrypoint}: ${result.stderr}`);
        if (!supported) assert.match(result.stderr, /does not support maintenance/u);
      }
    }
  } finally {
    rmSync(fixture, { recursive: true, force: true });
  }
});
