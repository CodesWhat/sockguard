import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { test } from "node:test";

const root = resolve(import.meta.dirname, "..");
const ci = readFileSync(join(root, ".github/workflows/ci-verify.yml"), "utf8");
const security = readFileSync(join(root, ".github/workflows/security-grype.yml"), "utf8");
function job(source, name) {
  return source.match(
    new RegExp(`^  ${name}:\\n([\\s\\S]*?)(?=^  [\\w-]+:|$(?![\\s\\S]))`, "m"),
  )?.[1];
}
for (const [source, names] of [
  [ci, ["shellcheck", "dependency-review", "gitleaks", "commit-message"]],
  [security, ["govulncheck", "grype-deps"]],
]) {
  for (const name of names) {
    test(`${name} denies both sudo and container access`, () => {
      const body = job(source, name);
      assert.ok(body);
      assert.match(body, /^ +disable-sudo-and-containers: true$/m);
    });
  }
}
const step = ci
  .slice(ci.indexOf("      - name: Verify fresh socket-volume startup"))
  .split("\n      - name:")[0];
const startup = step
  .split("        run: |\n")[1]
  .split("\n")
  .map((line) => line.replace(/^ {10}/, ""))
  .join("\n");
for (const [label, mode, requestFails, expected] of [
  ["non-root consumer", "65532:65532 600", "0", 0],
  ["wrong ownership", "0:0 666", "0", 1],
  ["consumer request failure", "65532:65532 600", "1", 1],
]) {
  test(`fresh socket startup checks ${label}`, (t) => {
    const dir = mkdtempSync(join(tmpdir(), "sockguard-ci-socket-"));
    t.after(() => rmSync(dir, { recursive: true, force: true }));
    writeFileSync(
      join(dir, "docker"),
      `#!/bin/sh
printf '%s\\n' "$*" >> "$CALLS"
case "$1:$2" in
  volume:create) echo fixture ;;
  volume:inspect) echo /fixture ;;
  run:--detach) echo fixture ;;
  run:--rm)
    case " $* " in *" --user 65532:65532 "*) ;; *) exit 1 ;; esac
    case " $* " in *":/var/run/sockguard:ro "*) ;; *) exit 1 ;; esac
    [ "$REQUEST_FAILS" = 0 ] || exit 1
    echo OK ;;
  inspect:*) echo true ;;
  wait:*) exit 1 ;;
  pull:*) ;;
  rm:*|volume:rm) ;;
  *) exit 1 ;;
esac
`,
      { mode: 0o755 },
    );
    writeFileSync(join(dir, "stat"), "#!/bin/sh\necho 123\n", { mode: 0o755 });
    writeFileSync(
      join(dir, "sudo"),
      `#!/bin/sh
case "$1" in
  test) exit 0 ;;
  stat) echo "$OWNER_MODE" ;;
  curl) echo OK ;;
  *) exit 1 ;;
esac
`,
      { mode: 0o755 },
    );
    writeFileSync(join(dir, "timeout"), "#!/bin/sh\nexit 124\n", { mode: 0o755 });
    const result = spawnSync("bash", ["-c", startup], {
      cwd: root,
      encoding: "utf8",
      timeout: 5000,
      env: {
        PATH: `${dir}:${process.env.PATH}`,
        CALLS: join(dir, "calls"),
        OWNER_MODE: mode,
        REQUEST_FAILS: requestFails,
        GITHUB_RUN_ID: "fixture",
        GITHUB_RUN_ATTEMPT: "1",
      },
    });
    assert.equal(result.status, expected, result.stdout + result.stderr);
    if (expected === 0) {
      const calls = readFileSync(join(dir, "calls"), "utf8");
      assert.match(calls, /run --rm --user 65532:65532 .*:ro /);
      assert.match(calls, /curlimages\/curl:[^ ]+@sha256:[a-f0-9]{64}/);
    }
  });
}

test("the shared scanner exception stays bound to its reviewed upstream contract", () => {
  const contract = JSON.parse(
    readFileSync(join(root, "scripts/testdata/shared-workflow-security.json"), "utf8"),
  );
  const caller = job(ci, "go-ci");
  assert.ok(caller.includes(`uses: ${contract.source}`));
  const withSection = caller.split("    with:\n")[1];
  for (const match of withSection.matchAll(/^ {6}([\w-]+):/gm)) {
    assert.ok(contract.inputs.includes(match[1]), `unsupported upstream input: ${match[1]}`);
  }
  assert.ok(!contract.inputs.includes("workflow-security-disable-sudo"));
  assert.match(contract.job, /^ {6}actions: read$/m);
  assert.match(contract.job, /^ {6}contents: read$/m);
  assert.doesNotMatch(contract.job, /: write|secrets: inherit/);
  assert.match(contract.job, /persist-credentials: false/);
  assert.match(contract.job, /online-audits: false/);
  assert.doesNotMatch(contract.job, /^ +run:|disable-sudo/m);
  const docs = readFileSync(join(root, "docs/content/docs/security.mdx"), "utf8");
  assert.ok(docs.includes(contract.source.split("@")[1]));
  assert.ok(docs.includes("those runner capabilities remain available"));
});
