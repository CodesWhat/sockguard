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

test("tag releases publish and verify the extracted changelog entry", () => {
  const config = read("app/.goreleaser.yaml");
  const workflow = read(".github/workflows/release-from-tag.yml");
  const goreleaser = workflowJob(workflow, "goreleaser");

  assert.match(config, /^changelog:\n(?: {2}.*\n)*? {2}disable: false\b/m);
  assert.match(goreleaser, /args: release --clean --release-notes=\.\.\/release-notes\.md/);
  assert.match(goreleaser, /^ {6}- name: Publish and verify release notes$/m);
  assert.match(goreleaser, /gh release edit "\$\{RELEASE_TAG\}" --notes-file release-notes\.md/);
  assert.match(goreleaser, /gh release view "\$\{RELEASE_TAG\}" --json body --jq '\.body'/);
  assert.match(goreleaser, /\[\[ "\$\{published_body\}" != "\$\{expected_body\}" \]\]/);
});

test("image provenance can persist its artifact metadata storage record", () => {
  const workflow = read(".github/workflows/release-from-tag.yml");
  const release = workflowJob(workflow, "release");

  assert.match(release, /^ {6}artifact-metadata: write$/m);
  assert.match(release, /^ {6}attestations: write$/m);
  assert.match(release, /^ {10}push-to-registry: true$/m);
});

test("the release guide includes the publication readback gates", () => {
  const releasing = read("RELEASING.md");

  assert.match(
    releasing,
    /reads the published body back and compares it to the extracted CHANGELOG entry/,
  );
  assert.match(releasing, /persists the GHCR image's linked artifact metadata/);
  assert.match(releasing, /GitHub release notes match the tagged CHANGELOG entry/);
});

test("the chart image pin lands on the development branch and never on main", () => {
  const workflow = read(".github/workflows/release-from-tag.yml");
  const release = workflowJob(workflow, "release");
  const pin = workflowJob(workflow, "pin-chart-digest");

  // main only advances through a promotion PR, so the pin commit has to go
  // to the branch renovate.json names. Every cut through v2.2.0 (#430, #492)
  // did this by hand afterwards.
  assert.match(pin, /^ {4}needs: \[release, verify-published, verify-homebrew\]$/m);
  assert.match(pin, /^ {4}if: \$\{\{ !contains\(github\.ref_name, '-'\) \}\}$/m);
  assert.match(pin, /^ {6}contents: write {2}# the pin commit/m);
  assert.match(pin, /bash scripts\/ci\/active-dev-branch\.sh renovate\.json/);
  assert.match(pin, /git push origin "HEAD:refs\/heads\/\$\{TARGET_BRANCH\}"/);
  assert.doesNotMatch(pin, /github\.event\.repository\.default_branch \}\}"/);

  // The digest it writes has to be the one the publish job pushed, not
  // merely whatever the tag resolves to when this job runs.
  assert.match(
    release,
    /^ {4}outputs:\n(?: {6}#.*\n)* {6}digest: \$\{\{ steps\.digest\.outputs\.value \}\}$/m,
  );
  assert.match(pin, /BUILD_DIGEST: \$\{\{ needs\.release\.outputs\.digest \}\}/);
  assert.match(pin, /if \[ "\$\{digest\}" != "\$\{BUILD_DIGEST\}" \]; then/);
  assert.match(pin, /refusing to pin a digest this pipeline did not push/);

  assert.match(pin, /node scripts\/pin-chart-image-digest\.mjs \\/);
  assert.match(pin, /node --test scripts\/release-metadata\.test\.mjs/);
  assert.match(
    pin,
    /git commit -m "chore\(chart\): pin the \$\{RELEASE_VERSION\} image to its multi-arch digest"/,
  );
  assert.match(pin, /nothing to commit/);
});
