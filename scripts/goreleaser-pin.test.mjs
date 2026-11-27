import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const read = (path) => readFileSync(new URL(`../${path}`, import.meta.url), "utf8");

test("the release workflow and the snapshot check pin the same GoReleaser", () => {
  const workflow = read(".github/workflows/release-from-tag.yml");
  const pin = workflow.match(/^ {2}GORELEASER_VERSION: v(\d+)\.(\d+)\.(\d+)$/m);

  assert.ok(pin, "release-from-tag.yml must pin GORELEASER_VERSION to an exact version");
  assert.equal(Number(pin[1]), 2, "GoReleaser v2 is the supported major");

  const snapshotPin = read("scripts/ci/go-release-check.sh").match(
    /goreleaser\/v2@(v\d+\.\d+\.\d+)/u,
  );
  assert.equal(
    snapshotPin?.[1],
    `v${pin.slice(1).join(".")}`,
    "snapshot and tagged publisher must use the same GoReleaser release",
  );
});
