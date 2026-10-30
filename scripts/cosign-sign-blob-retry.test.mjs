import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const SCRIPT = join(ROOT, "scripts", "cosign-sign-blob-retry.sh");
const GORELEASER = join(ROOT, "app", ".goreleaser.yaml");
const RELEASE_WORKFLOW = join(ROOT, ".github", "workflows", "release-from-tag.yml");

// Fake cosign: logs each call, records whether the bundle existed when it was
// called, writes a partial bundle, and fails the first FAILS calls.
const FAKE_COSIGN = `#!/usr/bin/env bash
dir="$FAKE_DIR"
n=$(( $(cat "$dir/calls" 2>/dev/null || echo 0) + 1 ))
echo "$n" > "$dir/calls"
echo "$*" >> "$dir/args"
for a in "$@"; do
  case "$a" in --bundle=*) b="\${a#--bundle=}" ;; esac
done
if [ -e "$b" ]; then echo "stale" >> "$dir/stale"; fi
if [ "$n" -le "$FAILS" ]; then
  echo partial > "$b"
  exit 1
fi
echo ok > "$b"
`;

function run(fails) {
  const dir = mkdtempSync(join(tmpdir(), "cosign-retry-"));
  try {
    const bin = join(dir, "bin");
    spawnSync("mkdir", ["-p", bin]);
    writeFileSync(join(bin, "cosign"), FAKE_COSIGN);
    writeFileSync(join(bin, "sleep"), '#!/usr/bin/env bash\necho "$1" >> "$FAKE_DIR/sleeps"\n');
    chmodSync(join(bin, "cosign"), 0o755);
    chmodSync(join(bin, "sleep"), 0o755);
    const bundle = join(dir, "artifact.sigstore.json");
    const env = Object.fromEntries(
      Object.entries(process.env).filter(([k]) => !k.startsWith("GIT_")),
    );
    const result = spawnSync(
      "bash",
      [SCRIPT, "--yes", `--bundle=${bundle}`, join(dir, "artifact")],
      {
        env: { ...env, PATH: `${bin}:${process.env.PATH}`, FAKE_DIR: dir, FAILS: String(fails) },
        encoding: "utf8",
      },
    );
    const read = (name) => {
      try {
        return readFileSync(join(dir, name), "utf8");
      } catch {
        return "";
      }
    };
    return {
      result,
      calls: Number(read("calls").trim() || 0),
      args: read("args"),
      stale: read("stale"),
      sleeps: read("sleeps").trim().split("\n").filter(Boolean),
      bundle: read("artifact.sigstore.json").trim(),
    };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

describe("cosign-sign-blob-retry.sh", () => {
  it("is executable and passes its arguments to cosign sign-blob", () => {
    assert.ok((statSync(SCRIPT).mode & 0o111) !== 0, "must be executable");
    const r = run(0);
    assert.equal(r.result.status, 0);
    assert.equal(r.calls, 1);
    assert.match(r.args, /^sign-blob --yes --bundle=.*artifact\.sigstore\.json .*artifact$/mu);
    assert.deepEqual(r.sleeps, []);
  });

  it("retries once, removing the partial bundle first", () => {
    const r = run(1);
    assert.equal(r.result.status, 0);
    assert.equal(r.calls, 2);
    assert.equal(r.stale, "", "the retry must not see the failed attempt's bundle");
    assert.deepEqual(r.sleeps, ["30"]);
    assert.equal(r.bundle, "ok");
    assert.match(r.result.stdout, /::warning::cosign sign-blob attempt 1 failed, retrying in 30s/u);
  });

  it("gives up after three failed attempts", () => {
    const r = run(3);
    assert.equal(r.result.status, 1);
    assert.equal(r.calls, 3);
    assert.deepEqual(r.sleeps, ["30", "60"]);
    assert.match(r.result.stdout, /::error::cosign sign-blob failed after 3 attempts/u);
  });
});

describe("release signing wiring", () => {
  it("routes both GoReleaser signs entries through the retry wrapper", () => {
    const config = readFileSync(GORELEASER, "utf8");
    const signs = config.slice(config.indexOf("\nsigns:"), config.indexOf("\nsnapshot:"));
    const entries = signs.split(/^ {2}- id: /mu).slice(1);
    assert.equal(entries.length, 2);
    for (const entry of entries) {
      assert.match(entry, /^ {4}cmd: bash$/mu);
      assert.match(entry, /^ {6}- "\.\.\/scripts\/cosign-sign-blob-retry\.sh"$/mu);
      assert.ok(!/^ {6}- sign-blob$/mu.test(entry), "the wrapper supplies sign-blob");
      assert.match(entry, /--bundle=\$\{signature\}/u);
    }
  });

  it("loads the Sigstore trust root with a three-attempt chain before GoReleaser runs", () => {
    const wf = readFileSync(RELEASE_WORKFLOW, "utf8");
    const at = (name) => wf.indexOf(`- name: ${name}\n`);
    const names = [
      "Install cosign",
      "Initialize Sigstore trust root",
      "Wait before Initialize Sigstore trust root retry",
      "Initialize Sigstore trust root (retry)",
      "Wait before Initialize Sigstore trust root final retry",
      "Initialize Sigstore trust root (final retry)",
      "Run GoReleaser",
    ];
    const positions = names.map(at);
    assert.ok(
      positions.every((p) => p >= 0),
      `missing step in ${JSON.stringify(positions)}`,
    );
    assert.deepEqual(
      [...positions].sort((a, b) => a - b),
      positions,
      "steps out of order",
    );
    const chain = wf.slice(positions[1], positions[6]);
    assert.equal(chain.match(/run: cosign initialize$/gmu)?.length, 3);
    assert.match(chain, /id: cosign_init\n\s+continue-on-error: true/u);
    assert.match(
      chain,
      /id: cosign_init_retry\n\s+if: steps\.cosign_init\.outcome == 'failure'\n\s+continue-on-error: true/u,
    );
    assert.match(chain, /run: sleep 30/u);
    assert.match(chain, /run: sleep 60/u);
    const final = chain.slice(chain.indexOf("(final retry)"));
    assert.ok(!final.includes("continue-on-error"), "final attempt must fail the job");
  });
});
