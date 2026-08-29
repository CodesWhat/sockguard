import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const read = (path) => readFileSync(new URL(`../${path}`, import.meta.url), "utf8");

const workflowJob = (workflow, name) => {
  const lines = workflow.split("\n");
  const start = lines.indexOf(`  ${name}:`);
  assert.notEqual(start, -1, `workflow job ${name} must exist`);
  const relativeEnd = lines.slice(start + 1).findIndex((line) => /^ {2}[a-z0-9_-]+:$/.test(line));
  const end = relativeEnd === -1 ? lines.length : start + 1 + relativeEnd;
  return lines.slice(start, end).join("\n");
};

test("GoReleaser publishes the sockguard binary to the CodesWhat Homebrew tap", () => {
  const config = read("app/.goreleaser.yaml");

  assert.match(config, /^homebrew_casks:$/m);
  assert.match(config, /^ {2}- name: sockguard$/m);
  assert.match(config, /^ {4}ids:\n {6}- default$/m);
  assert.match(config, /^ {4}binaries:\n {6}- sockguard$/m);
  assert.match(config, /^ {4}skip_upload: auto$/m);
  assert.match(config, /^ {6}owner: CodesWhat$/m);
  assert.match(config, /^ {6}name: homebrew-tap$/m);
  assert.match(config, /^ {6}token: "{{ \.Env\.HOMEBREW_TAP_TOKEN }}"$/m);
  assert.match(config, /^ {4}hooks:\n {6}post:\n {8}install: \|$/m);
  assert.match(
    config,
    /system_command "\/usr\/bin\/xattr", args: \["-dr", "com\.apple\.quarantine", "#\{staged_path\}\/sockguard"\]/,
  );
});

test("stable releases publish and smoke-test the Homebrew cask", () => {
  const workflow = read(".github/workflows/release-from-tag.yml");
  const goreleaser = workflowJob(workflow, "goreleaser");
  const verifyHomebrew = workflowJob(workflow, "verify-homebrew");

  assert.match(goreleaser, /^ {10}HOMEBREW_TAP_TOKEN: \$\{\{ secrets\.HOMEBREW_TAP_TOKEN \}\}$/m);
  assert.match(goreleaser, /^ {8}if: \$\{\{ !contains\(github\.ref_name, '-'\) \}\}$/m);
  assert.match(goreleaser, /test -n "\$\{HOMEBREW_TAP_TOKEN\}"/);
  assert.match(goreleaser, /HOMEBREW_TAP_TOKEN is required/);
  assert.match(verifyHomebrew, /^ {4}needs: \[release\]$/m);
  assert.match(verifyHomebrew, /^ {4}if: \$\{\{ !contains\(github\.ref_name, '-'\) \}\}$/m);
  assert.match(verifyHomebrew, /^ {4}runs-on: macos-15$/m);
  assert.match(verifyHomebrew, /^ {6}HOMEBREW_CASK_OPTS: ""$/m);
  assert.match(verifyHomebrew, /brew install --cask codeswhat\/tap\/sockguard/);
  assert.match(verifyHomebrew, /^ {10}RELEASE_VERSION: \$\{\{ github\.ref_name \}\}$/m);
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

test("the release workflow pins GoReleaser to v2.18.0 or newer", () => {
  // GoReleaser < 2.16 emitted `on_intel` before `on_arm` and `url` before
  // `sha256` inside each block, plus a blank line between `on_macos` and
  // `on_linux`. That is 13 Cask/StanzaOrder and Cask/StanzaGrouping offences
  // on a file every release overwrites, so it can only be fixed here.
  // Downgrading past 2.18.0 reintroduces all of them.
  const workflow = read(".github/workflows/release-from-tag.yml");
  const pin = workflow.match(/^ {2}GORELEASER_VERSION: v(\d+)\.(\d+)\.(\d+)$/m);

  assert.ok(pin, "release-from-tag.yml must pin GORELEASER_VERSION to an exact version");

  const [major, minor] = pin.slice(1).map(Number);
  assert.equal(major, 2, "GoReleaser v2 is the supported major");
  assert.ok(minor >= 18, `GORELEASER_VERSION must be at least v2.18.0, got ${pin[0].trim()}`);
});
