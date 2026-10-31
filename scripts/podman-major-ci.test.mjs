import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import test from "node:test";

const workflow = readFileSync(
  new URL("../.github/workflows/quality-integration-podman.yml", import.meta.url),
  "utf8",
);
const guard = workflow.match(
  /jq -e --arg major "\$PODMAN_MAJOR" '([\s\S]+?)' artifacts\/podman\/version\.json/u,
)?.[1];
assert.ok(guard, "the live daemon version guard must exist");

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
