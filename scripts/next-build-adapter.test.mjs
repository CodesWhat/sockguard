import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";

const root = resolve(import.meta.dirname, "..");

test("the copied docs export isolates the deployment adapter while the website retains it", () => {
  const fixture = mkdtempSync(join(tmpdir(), "sockguard-build-adapter-"));
  try {
    const next = join(fixture, "next");
    writeFileSync(
      next,
      "#!/usr/bin/env node\nprocess.stdout.write(JSON.stringify({adapter:process.env.NEXT_ADAPTER_PATH ?? null}));\n",
    );
    chmodSync(next, 0o755);
    for (const [workspace, expected] of [
      ["docs", null],
      ["website", "/platform/deployment-adapter"],
    ]) {
      const { scripts } = JSON.parse(readFileSync(join(root, workspace, "package.json"), "utf8"));
      const result = spawnSync("sh", ["-c", scripts.build], {
        cwd: join(root, workspace),
        encoding: "utf8",
        env: {
          ...process.env,
          PATH: `${fixture}:${process.env.PATH}`,
          NEXT_ADAPTER_PATH: "/platform/deployment-adapter",
        },
      });
      assert.equal(result.status, 0, `${workspace}: ${result.stderr}`);
      assert.equal(JSON.parse(result.stdout).adapter, expected, workspace);
    }
  } finally {
    rmSync(fixture, { recursive: true, force: true });
  }
});
