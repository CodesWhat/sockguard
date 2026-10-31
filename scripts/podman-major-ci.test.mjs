import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

const workflow = readFileSync(
  new URL("../.github/workflows/quality-integration-podman.yml", import.meta.url),
  "utf8",
);
const guard = workflow.match(
  /jq -e --arg major "\$PODMAN_MAJOR" '([\s\S]+?)' artifacts\/podman\/version\.json/u,
)?.[1];
assert.ok(guard, "the live daemon version guard must exist");

test("native CI fails when go test fails before tee", () => {
  const body = workflow.match(
    /- name: Run native API integration suites\n\s+working-directory: app\n\s+run: \|\n([\s\S]+?)\n {6}- name:/u,
  )?.[1];
  assert.ok(body);
  const dir = mkdtempSync(join(tmpdir(), "sockguard-podman-exit-"));
  try {
    mkdirSync(join(dir, "app"));
    mkdirSync(join(dir, "artifacts/podman"), { recursive: true });
    const result = spawnSync(
      "bash",
      ["-e", "-c", 'go() { printf \'{"Action":"fail"}\\n\'; return 17; }\n' + body],
      { cwd: join(dir, "app"), encoding: "utf8", timeout: 5000 },
    );
    assert.ifError(result.error);
    assert.equal(result.status, 17, result.stdout + result.stderr);
    assert.match(readFileSync(join(dir, "artifacts/podman/tests.jsonl"), "utf8"), /"fail"/u);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

for (const [mode, expectedCalls, succeeds] of [
  ["healthy", 5, true],
  ["flapping", 8, true],
  ["unreachable", 60, false],
]) {
  test(`native CI socket readiness: ${mode}`, () => {
    const body = workflow.match(
      /- name: Verify native socket is settled\n\s+run: \|\n([\s\S]+?)\n {6}- name:/u,
    )?.[1];
    assert.ok(body, "native suite must verify a settled socket after pre-pull");
    const dir = mkdtempSync(join(tmpdir(), "sockguard-podman-readiness-"));
    try {
      const countFile = join(dir, "count");
      writeFileSync(join(dir, "sudo"), "#!/bin/sh\nexit 0\n", { mode: 0o755 });
      writeFileSync(join(dir, "sleep"), "#!/bin/sh\nexit 0\n", { mode: 0o755 });
      writeFileSync(
        join(dir, "curl"),
        '#!/bin/sh\ncount=0\nif [ -f "$PROBE_COUNT_FILE" ]; then count=$(cat "$PROBE_COUNT_FILE"); fi\ncount=$((count+1))\nprintf "%s" "$count" > "$PROBE_COUNT_FILE"\ncase "$PROBE_MODE" in unreachable) exit 1;; flapping) [ "$count" -ne 3 ];; *) exit 0;; esac\n',
        { mode: 0o755 },
      );
      const result = spawnSync("bash", ["-euo", "pipefail", "-c", body], {
        env: {
          ...process.env,
          PATH: `${dir}:${process.env.PATH}`,
          PROBE_COUNT_FILE: countFile,
          PROBE_MODE: mode,
          SOCKGUARD_TEST_PODMAN_SOCKET: join(dir, "podman.sock"),
        },
        encoding: "utf8",
        timeout: 5000,
      });
      assert.ifError(result.error);
      assert.equal(result.status === 0, succeeds, result.stderr);
      assert.equal(Number(readFileSync(countFile, "utf8")), expectedCalls);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
}

for (const [name, major, payload, allowed] of [
  ["Podman 5", "5", { Components: [{ Name: "Podman Engine", Version: "5.8.9" }] }, true],
  ["Podman 6", "6", { Components: [{ Name: "Podman Engine", Version: "6.1.3" }] }, true],
  ["wrong major", "6", { Components: [{ Name: "Podman Engine", Version: "5.8.9" }] }, false],
  ["Docker daemon", "6", { Components: [{ Name: "Engine", Version: "29.9.1" }] }, false],
  ["missing version", "6", { Components: [{ Name: "Podman Engine" }] }, false],
  ["missing components", "6", {}, false],
  ["invalid JSON", "6", "not JSON", false],
  [
    "contradictory engines",
    "6",
    {
      Components: [
        { Name: "Podman Engine", Version: "6.1.3" },
        { Name: "Podman Engine", Version: "5.8.9" },
      ],
    },
    false,
  ],
]) {
  test(`native CI version guard: ${name}`, () => {
    const result = spawnSync("jq", ["-e", "--arg", "major", major, guard], {
      input: typeof payload === "string" ? payload : JSON.stringify(payload),
      encoding: "utf8",
      timeout: 5000,
    });
    assert.ifError(result.error);
    assert.equal(result.status === 0, allowed, result.stderr);
  });
}
