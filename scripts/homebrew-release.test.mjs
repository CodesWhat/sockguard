import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const read = (path) => readFileSync(new URL(`../${path}`, import.meta.url), "utf8");

const workflowJob = (workflow, name) => {
  const lines = workflow.split("\n");
  const start = lines.indexOf(`  ${name}:`);
  assert.notEqual(start, -1, `workflow job ${name} must exist`);
  const relativeEnd = lines.slice(start + 1).findIndex((line) => /^  [a-z0-9_-]+:$/.test(line));
  const end = relativeEnd === -1 ? lines.length : start + 1 + relativeEnd;
  return lines.slice(start, end).join("\n");
};

test("GoReleaser publishes the sockguard binary to the CodesWhat Homebrew tap", () => {
  const config = read("app/.goreleaser.yaml");

  assert.match(config, /^homebrew_casks:$/m);
  assert.match(config, /^  - name: sockguard$/m);
  assert.match(config, /^    ids:\n      - default$/m);
  assert.match(config, /^    binaries:\n      - sockguard$/m);
  assert.match(config, /^    skip_upload: auto$/m);
  assert.match(config, /^      owner: CodesWhat$/m);
  assert.match(config, /^      name: homebrew-tap$/m);
  assert.match(config, /^      token: "{{ \.Env\.HOMEBREW_TAP_TOKEN }}"$/m);
  assert.match(config, /^    hooks:\n      post:\n        install: \|$/m);
  assert.match(
    config,
    /system_command "\/usr\/bin\/xattr", args: \["-dr", "com\.apple\.quarantine", "#\{staged_path\}\/sockguard"\]/,
  );
});

test("stable releases publish and smoke-test the Homebrew cask", () => {
  const workflow = read(".github/workflows/release-from-tag.yml");
  const goreleaser = workflowJob(workflow, "goreleaser");
  const verifyHomebrew = workflowJob(workflow, "verify-homebrew");

  assert.match(goreleaser, /^          HOMEBREW_TAP_TOKEN: \$\{\{ secrets\.HOMEBREW_TAP_TOKEN \}\}$/m);
  assert.match(goreleaser, /^        if: \$\{\{ !contains\(github\.ref_name, '-'\) \}\}$/m);
  assert.match(goreleaser, /test -n "\$\{HOMEBREW_TAP_TOKEN\}"/);
  assert.match(goreleaser, /HOMEBREW_TAP_TOKEN is required/);
  assert.match(verifyHomebrew, /^    needs: \[release\]$/m);
  assert.match(verifyHomebrew, /^    if: \$\{\{ !contains\(github\.ref_name, '-'\) \}\}$/m);
  assert.match(verifyHomebrew, /^    runs-on: macos-15$/m);
  assert.match(verifyHomebrew, /^      HOMEBREW_CASK_OPTS: ""$/m);
  assert.match(verifyHomebrew, /brew install --cask codeswhat\/tap\/sockguard/);
  assert.match(verifyHomebrew, /^          RELEASE_VERSION: \$\{\{ github\.ref_name \}\}$/m);
  assert.match(verifyHomebrew, /sockguard version -o json/);
  assert.match(verifyHomebrew, /\.version == \$version/);
  assert.match(verifyHomebrew, /xattr -p com\.apple\.quarantine/);
  assert.match(verifyHomebrew, /brew uninstall --cask sockguard/);
});

test("branch CI renders and inspects the generated Homebrew cask", () => {
  const goreleaserCheck = read("scripts/ci/go-release-check.sh");

  assert.match(goreleaserCheck, /release --snapshot --clean --skip="\$\{skip\}"/);
  assert.match(goreleaserCheck, /cask="dist\/homebrew\/Casks\/sockguard\.rb"/);
  assert.match(goreleaserCheck, /test -f "\$\{cask\}"/);
  assert.match(goreleaserCheck, /cask "sockguard" do/);
  assert.match(goreleaserCheck, /com\.apple\.quarantine/);
});

test("public and maintainer docs describe the Homebrew release path", () => {
  const installCommand = "brew install --cask codeswhat/tap/sockguard";
  const readme = read("README.md");
  const gettingStarted = read("docs/content/docs/getting-started.mdx");
  const releasing = read("RELEASING.md");
  const changelog = read("CHANGELOG.md");

  assert.match(readme, new RegExp(installCommand));
  assert.match(readme, /not yet Apple notarized/);
  assert.match(gettingStarted, new RegExp(installCommand));
  assert.match(gettingStarted, /not yet signed and notarized with an Apple Developer ID/);
  assert.match(gettingStarted, /brew upgrade --cask sockguard/);
  assert.match(gettingStarted, /brew uninstall --cask sockguard/);
  assert.match(releasing, /HOMEBREW_TAP_TOKEN/);
  assert.match(releasing, /verify-homebrew/);
  assert.match(changelog, /^- \*\*Homebrew distribution/m);
});
