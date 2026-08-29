// scripts/tri-tool-conformance-run-matrix.test.mjs
//
// Wires scripts/tri-tool-conformance/run-matrix.sh --self-test into `npm
// test` (package.json's test script globs scripts/*.test.mjs, not the
// tri-tool-conformance/ subdirectory, so this thin wrapper lives one level
// up rather than renaming the harness's own layout). --self-test exercises
// the route normalizer (normalize-routes.jq) and the known-routes.json
// tripwire diff against testdata/access-log-fixture.jsonl -- pure jq, no
// Docker, no network -- so it can run on every push the same way
// verify-published-release.sh's --dry-run does.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(scriptDir, "..");
const scriptPath = resolve(scriptDir, "tri-tool-conformance", "run-matrix.sh");
const workflowPath = resolve(repoRoot, ".github", "workflows", "quality-tri-tool-conformance.yml");
const clockPreloadPath = resolve(scriptDir, "tri-tool-conformance", "controller-clock-offset.cjs");

function runSelfTest() {
  return spawnSync("bash", [scriptPath, "--self-test"], {
    cwd: repoRoot,
    encoding: "utf8",
  });
}

describe("tri-tool-conformance/run-matrix.sh --self-test", () => {
  it("passes the route normalizer + tripwire diff self-test", () => {
    const result = runSelfTest();

    assert.equal(result.status, 0, `stdout:\n${result.stdout}\nstderr:\n${result.stderr}`);
    assert.match(result.stdout, /== self-test OK ==/);
    assert.match(result.stdout, /PASS: known-routes\.json parses as valid JSON/);
    assert.match(
      result.stdout,
      /PASS: normalizer produced the expected 6 route shapes from the fixture/,
    );
    assert.match(
      result.stdout,
      /PASS: diff logic isolated the fixture's one deliberately-unknown route \(GET \/containers\/\*\/attach\)/,
    );
    assert.match(
      result.stdout,
      /PASS: every other fixture route is already recognized in known-routes\.json/,
    );
  });

  it("loads the tagged-artifact identity acceptance lane", () => {
    const script = readFileSync(scriptPath, "utf8");

    for (const assertion of [
      "identity-enrollment",
      "identity-overlapping-key-rotation",
      "identity-revocation",
      "identity-sighup-reload",
      "identity-clock-skew-recovery",
    ]) {
      assert.match(script, new RegExp(`record_result \\"?\\$\\{?name\\}?.*|${assertion}`));
    }
    assert.match(script, /assert_identity_acceptance/);
    assert.match(script, /X-Portwing-Reason.*timestamp-skew|timestamp-skew.*X-Portwing-Reason/s);
    assert.match(script, /X-Portwing-Reason.*unknown-key|unknown-key.*X-Portwing-Reason/s);
  });

  it("does not expand a dependent local before Bash assigns it", () => {
    const script = readFileSync(scriptPath, "utf8");

    assert.doesNotMatch(
      script,
      /local[^\n]*private_file[^\n]*raw_file="\$\{private_file\}/,
      "set -u expands one local statement before assigning its earlier names",
    );
  });

  it("keeps the live registry readable by the rotation harness", () => {
    const script = readFileSync(scriptPath, "utf8");

    assert.match(script, /IDENTITY_RUNNER_GID="\$\(id -g\)"/);
    assert.match(script, /chmod 0640 "\$\{IDENTITY_AGENT_DIR\}\/authorized_keys"/);
    assert.match(script, /rm -f -- "\$\{IDENTITY_AGENT_DIR\}\/authorized_keys\.next"/);
    assert.match(
      script,
      /mv -f -- "\$\{IDENTITY_AGENT_DIR\}\/authorized_keys\.next" "\$\{IDENTITY_AGENT_DIR\}\/authorized_keys"/,
    );
  });

  it("mounts only agent-owned identity material into Portwing", () => {
    const script = readFileSync(scriptPath, "utf8");

    assert.match(script, /IDENTITY_AGENT_DIR="\$\{IDENTITY_DIR\}\/agent"/);
    assert.match(script, /IDENTITY_CONTROLLER_DIR="\$\{IDENTITY_DIR\}\/controller"/);
    assert.match(script, /-v "\$\{IDENTITY_AGENT_DIR\}:\/run\/identity"/);
    assert.doesNotMatch(script, /-v "\$\{IDENTITY_DIR\}:\/run\/identity"/);
    assert.match(script, /old_private="\$\{IDENTITY_CONTROLLER_DIR\}\/old\.pem"/);
    assert.match(
      script,
      /clock-offset.*IDENTITY_CONTROLLER_DIR|IDENTITY_CONTROLLER_DIR.*clock-offset/s,
    );
  });

  it("protects and removes raw keygen output on success and failure", () => {
    const script = readFileSync(scriptPath, "utf8");

    assert.match(script, /umask 077; docker run --rm/);
    assert.match(script, /rm -f -- "\$raw_file" "\$\{raw_file\}\.err"/);
    assert.match(script, /if ! \(umask 077; sed[\s\S]*rm -f -- "\$raw_file" "\$\{raw_file\}\.err"/);
  });

  it("can remove credentials after assigning them to container UIDs", () => {
    const script = readFileSync(scriptPath, "utf8");

    assert.match(script, /sudo rm -f -- "\$\{BUNDLE_DIR\}\/portwing_token\.txt"/);
  });

  it("matches the published Portwing JSON authentication reason", () => {
    const script = readFileSync(scriptPath, "utf8");

    assert.match(script, /'"reason":"unknown-key"'/);
    assert.match(script, /'"reason":"timestamp-skew"'/);
  });

  it("makes the clock control writable before restoring it", () => {
    const script = readFileSync(scriptPath, "utf8");

    assert.match(
      script,
      /chmod 0644 "\$\{IDENTITY_CONTROLLER_DIR\}\/clock-offset"\n\s+printf '%s\\n' 0/,
    );
  });

  it("replaces stale row logs before capturing diagnostics", () => {
    const script = readFileSync(scriptPath, "utf8");

    assert.match(script, /find "\$CONFORMANCE_LOG_DIR" -type f -delete/);
  });

  it("uploads the row logs with the JSON result", () => {
    const workflow = readFileSync(workflowPath, "utf8");

    assert.match(workflow, /conformance-\$\{\{ matrix\.row \}\}-logs\//);
  });

  it("faults and restores Date.now without restarting the controller", () => {
    const fixtureDir = mkdtempSync(join(tmpdir(), "tri-tool-clock-"));
    const offsetPath = join(fixtureDir, "offset");
    writeFileSync(offsetPath, "-120\n");

    try {
      const result = spawnSync(
        process.execPath,
        [
          "--require",
          clockPreloadPath,
          "-e",
          [
            'const fs = require("node:fs");',
            "const skewed = Date.now();",
            'fs.writeFileSync(process.env.TT_CLOCK_OFFSET_FILE, "0\\n");',
            "const recovered = Date.now();",
            "process.stdout.write(JSON.stringify({ skewed, recovered }));",
          ].join(" "),
        ],
        {
          encoding: "utf8",
          env: { ...process.env, TT_CLOCK_OFFSET_FILE: offsetPath },
        },
      );

      assert.equal(result.status, 0, `stdout:\n${result.stdout}\nstderr:\n${result.stderr}`);
      const { skewed, recovered } = JSON.parse(result.stdout);
      assert.ok(recovered - skewed >= 119_000, `${recovered} - ${skewed} should reflect recovery`);
      assert.ok(Math.abs(Date.now() - recovered) < 5_000, "recovered clock should match the host");
    } finally {
      rmSync(fixtureDir, { recursive: true, force: true });
    }
  });

  it("requires either --row or --self-test", () => {
    const result = spawnSync("bash", [scriptPath], { cwd: repoRoot, encoding: "utf8" });

    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /--row is required/);
  });

  it("rejects an unknown --row value", () => {
    const result = spawnSync("bash", [scriptPath, "--row", "bogus"], {
      cwd: repoRoot,
      encoding: "utf8",
    });

    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /unknown --row 'bogus'/);
  });
});
