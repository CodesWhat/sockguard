import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(scriptDir, "..");
const scriptPath = resolve(scriptDir, "verify-published-release.sh");

function runVerify(args, env = {}) {
  return spawnSync("bash", [scriptPath, ...args], {
    cwd: repoRoot,
    encoding: "utf8",
    env: { ...process.env, ...env },
  });
}

function writeExecutable(path, source) {
  writeFileSync(path, source);
  chmodSync(path, 0o755);
}

function escapeRegExp(source) {
  return source.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
}

describe("verify-published-release.sh", () => {
  it("prints the resolved plan in dry-run mode", () => {
    const result = runVerify(["--dry-run", "--tag", "v1.2.3"]);

    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /release tag:\s+v1\.2\.3/);
    assert.match(result.stdout, /ghcr\.io\/codeswhat\/sockguard:1\.2\.3/);
    assert.match(result.stdout, /docker\.io\/codeswhat\/sockguard:1\.2\.3/);
    assert.match(result.stdout, /quay\.io\/codeswhat\/sockguard:1\.2\.3/);
    assert.match(result.stdout, /sockguard-v1\.2\.3\.tar\.gz/);
  });

  // QA-6 exists to fail the tag when docs/content/docs/verification.mdx and
  // the pipeline drift apart. It can only do that for surfaces it actually
  // exercises: it verified the source tarball alone while the docs also
  // document the per-platform archive, checksums.txt, and provenance, so it
  // would have gone green on all three no matter what they did.
  it("covers the per-platform archive, checksums, and provenance", () => {
    const result = runVerify(["--dry-run", "--tag", "v1.2.3"]);

    assert.equal(result.status, 0, result.stderr);
    // Underscores and no `v`: the compiled GoReleaser archive, NOT the
    // `sockguard-v1.2.3.tar.gz` source snapshot asserted above.
    assert.match(result.stdout, /sockguard_1\.2\.3_linux_amd64\.tar\.gz/u);
    assert.match(result.stdout, /sockguard_1\.2\.3_linux_amd64\.tar\.gz\.sigstore\.json/u);
    assert.match(result.stdout, /checksums\.txt\.sigstore\.json/u);
    assert.match(result.stdout, /sha256sum --check --ignore-missing/u);
    assert.match(result.stdout, /gh attestation verify/u);
  });

  it("covers sigstore bundles without legacy detached assets", () => {
    const result = runVerify(["--dry-run", "--tag", "v1.2.3"]);

    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /sockguard-v1\.2\.3\.tar\.gz\.sigstore\.json/u);
    assert.match(result.stdout, /sockguard_1\.2\.3_linux_amd64\.tar\.gz\.sigstore\.json/u);
    assert.match(result.stdout, /checksums\.txt\.sigstore\.json/u);
    assert.match(result.stdout, /cosign verify-blob \\\s+--bundle/u);
    assert.doesNotMatch(result.stdout, /\.tar\.gz\.(?:sig|pem)(?:\s|$)/mu);
    assert.doesNotMatch(result.stdout, /checksums\.txt\.(?:sig|pem)(?:\s|$)/mu);
    assert.doesNotMatch(result.stdout, /--(?:signature|certificate)\s/u);
  });

  it("keeps the v2 release pipeline bundle-only", () => {
    const goreleaser = readFileSync(resolve(repoRoot, "app/.goreleaser.yaml"), "utf8");
    const workflow = readFileSync(
      resolve(repoRoot, ".github/workflows/release-from-tag.yml"),
      "utf8",
    );

    assert.equal(goreleaser.match(/signature: "\$\{artifact\}\.sigstore\.json"/gu)?.length, 2);
    assert.match(workflow, /--bundle "\$\{artifact\}\.sigstore\.json"/u);
    assert.doesNotMatch(goreleaser, /--(?:output-signature|output-certificate)/u);
    assert.doesNotMatch(goreleaser, /--new-bundle-format=false/u);
    assert.doesNotMatch(goreleaser, /signature: "\$\{artifact\}\.(?:sig|pem)"/u);
    assert.doesNotMatch(workflow, /--(?:output-signature|output-certificate)/u);
    assert.doesNotMatch(workflow, /--new-bundle-format=false/u);
    assert.doesNotMatch(workflow, /\$\{artifact\}\.(?:sig|pem)(?:"|\})/u);
  });

  it("executes bundle verification for every published blob", () => {
    const fixtureRoot = mkdtempSync(join(tmpdir(), "sockguard-release-qa-"));
    const binDir = join(fixtureRoot, "bin");
    const callLog = join(fixtureRoot, "calls.log");
    mkdirSync(binDir);

    writeExecutable(
      join(binDir, "cosign"),
      `#!/usr/bin/env bash\nprintf 'cosign %s\\n' "$*" >> "$FAKE_CALL_LOG"\n`,
    );
    writeExecutable(join(binDir, "docker"), "#!/usr/bin/env bash\nexit 0\n");
    writeExecutable(join(binDir, "sha256sum"), "#!/usr/bin/env bash\nexit 0\n");
    writeExecutable(
      join(binDir, "gh"),
      `#!/usr/bin/env bash
set -euo pipefail
printf 'gh %s\\n' "$*" >> "$FAKE_CALL_LOG"
if [ "$1 $2" = "release download" ]; then
  pattern=""
  directory=""
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --pattern) pattern="$2"; shift 2 ;;
      --dir) directory="$2"; shift 2 ;;
      *) shift ;;
    esac
  done
  : > "$directory/$pattern"
fi
`,
    );

    try {
      const result = runVerify(["--tag", "v2.0.0"], {
        FAKE_CALL_LOG: callLog,
        PATH: `${binDir}:${process.env.PATH}`,
      });
      assert.equal(result.status, 0, result.stderr);

      const calls = readFileSync(callLog, "utf8");
      for (const artifact of [
        "sockguard-v2.0.0.tar.gz",
        "sockguard_2.0.0_linux_amd64.tar.gz",
        "checksums.txt",
      ]) {
        assert.match(
          calls,
          new RegExp(
            `cosign verify-blob --bundle ${escapeRegExp(`${artifact}.sigstore.json`)} .* ${escapeRegExp(artifact)}$`,
            "mu",
          ),
        );
      }
    } finally {
      rmSync(fixtureRoot, { force: true, recursive: true });
    }
  });

  it("keeps the executable identity contract in the verification guide", () => {
    const docs = readFileSync(resolve(repoRoot, "docs/content/docs/verification.mdx"), "utf8");
    assert.match(
      docs,
      /\^https:\/\/github\.com\/CodesWhat\/sockguard\/\.github\/workflows\/release-from-tag\.yml@refs\/tags\/\.\+\$/u,
    );
    assert.ok(
      docs
        .split("\n")
        .some(
          (line) =>
            line.trim() ===
            "--certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \\",
        ),
    );
    assert.match(docs, /cosign verify-blob \\\s+--bundle/u);
  });

  it("embeds the documented identity regex and issuer", () => {
    const result = runVerify(["--dry-run", "--tag", "v1.2.3"]);

    assert.equal(result.status, 0, result.stderr);
    // The two strings that *must* match docs/content/docs/verification.mdx.
    assert.match(
      result.stdout,
      /\^https:\/\/github\.com\/CodesWhat\/sockguard\/\.github\/workflows\/release-from-tag\.yml@refs\/tags\/\.\+\$/,
    );
    assert.match(
      result.stdout,
      /^ {2}issuer:\s+https:\/\/token\.actions\.githubusercontent\.com$/m,
    );
  });

  it("lowercases GITHUB_REPOSITORY for the ghcr path", () => {
    // GHCR rejects mixed case in image paths; if someone passes an
    // organization name that contains capitals, the script must
    // normalize it for the ghcr.io tag while leaving the identity regex
    // (which is matched against the workflow run URL) in its original
    // case.
    const result = runVerify(["--dry-run", "--tag", "v0.1.0"], {
      GITHUB_REPOSITORY: "CodesWhat/Sockguard",
    });

    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /ghcr\.io\/codeswhat\/sockguard:0\.1\.0/);
    assert.match(
      result.stdout,
      /\^https:\/\/github\.com\/CodesWhat\/Sockguard\/\.github\/workflows\/release-from-tag\.yml@refs\/tags\/\.\+\$/,
    );
  });

  it("requires --tag", () => {
    const result = runVerify(["--dry-run"]);

    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /--tag .* is required/);
  });

  it("rejects unknown flags", () => {
    const result = runVerify(["--dry-run", "--tag", "v1.2.3", "--bogus"]);

    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /unknown flag --bogus/);
  });

  it("accepts --tag=value form", () => {
    const result = runVerify(["--dry-run", "--tag=v9.9.9-rc.1"]);

    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /release tag:\s+v9\.9\.9-rc\.1/);
    assert.match(result.stdout, /sockguard-v9\.9\.9-rc\.1\.tar\.gz/);
  });
});
