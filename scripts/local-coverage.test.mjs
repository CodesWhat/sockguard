import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";

test("the local Go hook enforces the CI production coverage floor", () => {
  const root = path.resolve(import.meta.dirname, "..");
  const hooks = fs.readFileSync(path.join(root, "lefthook.yml"), "utf8");
  const command = /^ {4}go-test:\n {6}run: (.+)$/mu.exec(hooks)?.[1];
  assert.ok(command, "Go test hook command is present");
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "local-coverage-"));
  try {
    fs.mkdirSync(path.join(tmp, "app"));
    fs.mkdirSync(path.join(tmp, "bin"));
    fs.mkdirSync(path.join(tmp, "scripts", "ci"), { recursive: true });
    fs.copyFileSync(
      path.join(root, "scripts", "ci", "go-test.sh"),
      path.join(tmp, "scripts", "ci", "go-test.sh"),
    );
    fs.writeFileSync(
      path.join(tmp, "bin", "go"),
      [
        "#!/bin/sh",
        'case "$1" in',
        "list) echo example.test/app/internal/filter ;;",
        "test)",
        '  for arg in "$@"; do',
        // biome-ignore lint/suspicious/noTemplateCurlyInString: this fixture uses shell parameter expansion.
        '    case "$arg" in -coverprofile=*) printf "mode: atomic\\nexample.test/app/internal/filter/filter.go:1.1,2.1 1 1\\n" > "${arg#-coverprofile=}" ;; esac',
        "  done ;;",
        'tool) printf "total: (statements) %s%%\\n" "$FAKE_COVERAGE" ;;',
        "*) exit 2 ;;",
        "esac",
        "",
      ].join("\n"),
      { mode: 0o755 },
    );
    for (const [coverage, succeeds] of [
      ["95.9", false],
      ["96.0", true],
    ]) {
      const result = spawnSync("bash", ["-c", command], {
        cwd: tmp,
        encoding: "utf8",
        timeout: 10000,
        env: {
          ...process.env,
          PATH: `${path.join(tmp, "bin")}:${process.env.PATH}`,
          COVERAGE_MIN: "96",
          FAKE_COVERAGE: coverage,
        },
      });
      assert.equal(result.error, undefined);
      assert.equal(result.status === 0, succeeds, result.stdout + result.stderr);
      assert.match(result.stdout + result.stderr, /floor 96|96% floor/u);
    }
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});
