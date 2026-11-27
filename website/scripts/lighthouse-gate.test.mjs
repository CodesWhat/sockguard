import assert from "node:assert/strict";
import { test } from "node:test";
import { evaluate } from "./lighthouse-gate.mjs";

test("passes at and above the threshold", () => {
  const { rows, failures } = evaluate("/", {
    performance: { score: 0.9 },
    accessibility: { score: 1 },
  });
  assert.deepEqual(failures, []);
  assert.deepEqual(
    rows.map((r) => r.score),
    [90, 100],
  );
});

test("fails below the threshold", () => {
  const { failures } = evaluate("/docs/x", {
    performance: { score: 0.89 },
    accessibility: { score: 0.95 },
  });
  assert.equal(failures.length, 1);
  assert.match(failures[0], /performance: 89/);
});

test("a missing score fails", () => {
  const { failures } = evaluate("/", { performance: { score: null } });
  assert.equal(failures.length, 2);
});
