import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

const scriptDir = dirname(fileURLToPath(import.meta.url));

describe("update-route-catalog.py", () => {
  it("passes its offline parser unit tests", () => {
    const result = spawnSync("python3", ["-I", resolve(scriptDir, "test_update_route_catalog.py")], {
      encoding: "utf8",
    });
    assert.equal(result.status, 0, result.stdout + result.stderr);
  });
});
