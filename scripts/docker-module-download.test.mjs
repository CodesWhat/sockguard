import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";

test("Docker module download retries failures within a bounded attempt count", () => {
  const dockerfile = fs.readFileSync(path.join(import.meta.dirname, "..", "Dockerfile"), "utf8");
  const start = dockerfile.indexOf("COPY go.mod go.sum ./\n") + "COPY go.mod go.sum ./\n".length;
  const end = dockerfile.indexOf("COPY app/", start);
  const script = dockerfile
    .slice(start, end)
    .trim()
    .replace(/^RUN\s+/u, "")
    .replace(/\\\n\s*/gu, " ");
  for (const failures of [2, 3, 0]) {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "docker-download-"));
    try {
      const count = path.join(tmp, "count");
      const sleeps = path.join(tmp, "sleeps");
      const limits = path.join(tmp, "limits");
      fs.writeFileSync(count, "0");
      fs.writeFileSync(sleeps, "");
      fs.writeFileSync(limits, "");
      const command = (name, body) =>
        fs.writeFileSync(path.join(tmp, name), `#!/bin/sh\n${body}\n`, { mode: 0o755 });
      command(
        "go",
        [
          'n=$(cat "$FAKE_COUNT"); n=$((n + 1)); echo "$n" > "$FAKE_COUNT"',
          'if [ "$n" -le "$FAKE_FAILURES" ]; then echo "transient download failure" >&2; exit 42; fi',
        ].join("\n"),
      );
      command("sleep", 'echo "$1" >> "$FAKE_SLEEPS"');
      command("timeout", ['echo "$1 $2 $3" >> "$FAKE_LIMITS"', "shift 3", 'exec "$@"'].join("\n"));
      const result = spawnSync("sh", ["-c", script], {
        encoding: "utf8",
        timeout: 10000,
        env: {
          ...process.env,
          PATH: `${tmp}:${process.env.PATH}`,
          FAKE_COUNT: count,
          FAKE_SLEEPS: sleeps,
          FAKE_LIMITS: limits,
          FAKE_FAILURES: String(failures),
        },
      });
      assert.equal(result.error, undefined);
      assert.equal(result.status === 0, failures < 3, result.stderr);
      const attempts = failures === 0 ? 1 : 3;
      assert.equal(Number(fs.readFileSync(count, "utf8")), attempts);
      assert.equal(fs.readFileSync(sleeps, "utf8"), failures === 0 ? "" : "5\n10\n");
      assert.equal(fs.readFileSync(limits, "utf8"), "-s KILL 120\n".repeat(attempts));
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  }
});
