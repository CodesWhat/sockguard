import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, it } from "node:test";

import { assertSafeNanoidVersions } from "./lockfile-security.mjs";

const currentLockfile = JSON.parse(
  readFileSync(resolve(import.meta.dirname, "../package-lock.json"), "utf8"),
);

function lockfileWithNanoid(version) {
  return {
    lockfileVersion: 3,
    packages: {
      "": {},
      "node_modules/nanoid": { version },
      "node_modules/example/node_modules/nanoid": { version: "5.1.6" },
    },
  };
}

describe("lockfile nanoid security contract", () => {
  it("accepts every resolved nanoid node in the current lockfile", () => {
    assert.doesNotThrow(() => assertSafeNanoidVersions(currentLockfile));
  });

  it("accepts the patched 3.x and 5.x release lines", () => {
    assert.doesNotThrow(() => assertSafeNanoidVersions(lockfileWithNanoid("3.3.18")));
  });

  it("rejects the exact vulnerable version from the frozen dev lockfile", () => {
    assert.throws(
      () => assertSafeNanoidVersions(lockfileWithNanoid("3.3.17")),
      /GHSA-2v37-7h3g-55p8.*node_modules\/nanoid.*3\.3\.17/,
    );
  });

  it("rejects the vulnerable 4.x release line", () => {
    assert.throws(
      () => assertSafeNanoidVersions(lockfileWithNanoid("4.0.0")),
      /GHSA-2v37-7h3g-55p8.*node_modules\/nanoid.*4\.0\.0/,
    );
  });

  it("fails closed when a nanoid node has no version", () => {
    const fixture = lockfileWithNanoid("3.3.18");
    delete fixture.packages["node_modules/nanoid"].version;

    assert.throws(
      () => assertSafeNanoidVersions(fixture),
      /node_modules\/nanoid.*missing a version/,
    );
  });

  it("fails closed when a nanoid version is malformed", () => {
    assert.throws(
      () => assertSafeNanoidVersions(lockfileWithNanoid("not-semver")),
      /node_modules\/nanoid.*malformed version/,
    );
  });

  it("fails closed when the packages map or nanoid nodes are missing", () => {
    assert.throws(() => assertSafeNanoidVersions({}), /packages map/);
    assert.throws(
      () => assertSafeNanoidVersions({ lockfileVersion: 3, packages: { "": {} } }),
      /no resolved nanoid nodes/,
    );
  });
});
