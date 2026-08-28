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
