import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const workflow = readFileSync(
  new URL("../.github/workflows/security-grype.yml", import.meta.url),
  "utf8",
);
const goMod = readFileSync(new URL("../go.mod", import.meta.url), "utf8");

const versionParts = (version) => version.split(".").map(Number);
const atLeast = (have, want) => {
  const a = versionParts(have);
  const b = versionParts(want);
  for (let i = 0; i < Math.max(a.length, b.length); i += 1) {
    const diff = (a[i] ?? 0) - (b[i] ?? 0);
    if (diff !== 0) return diff > 0;
  }
  return true;
};

test("gosec job guards the image Go version against go.mod", () => {
  assert.match(workflow, /- name: Guard gosec image Go version/);
  const guard = workflow.indexOf("- name: Guard gosec image Go version");
  const run = workflow.indexOf("- name: Run Gosec");
  assert.ok(guard !== -1 && run !== -1 && guard < run, "the guard must run before gosec");
});

test("declared gosec image Go covers go.mod's go directive", () => {
  const declared = workflow.match(/GOSEC_IMAGE_GO: "(\d+(?:\.\d+)+)"/)?.[1];
  const required = goMod.match(/^go (\d+(?:\.\d+)+)$/m)?.[1];
  assert.ok(declared, "GOSEC_IMAGE_GO is not declared");
  assert.ok(required, "go.mod has no go directive");
  assert.ok(
    atLeast(declared, required),
    `gosec image Go ${declared} is older than go.mod's ${required}`,
  );
});
