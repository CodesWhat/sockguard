import assert from "node:assert/strict";
import test from "node:test";

import { comparisonRows } from "./data/comparison-rows.ts";
import { features } from "./data/features.ts";

test("website features live in extracted data modules", () => {
  assert.equal(features.length, 6);
  assert.deepEqual(
    features.map((feature) => feature.title),
    [
      "Default-Deny Posture",
      "Granular Control",
      "Structured Logging",
      "YAML Configuration",
      "Tecnativa Compatible",
      "Minimal Attack Surface",
    ],
  );
  assert.deepEqual(
    [...new Set(features.map((feature) => feature.category))].sort(),
    ["control", "operations", "security"],
  );
});

test("website comparison rows live in extracted data modules", () => {
  assert.equal(comparisonRows.length, 7);

  const requestBodyRow = comparisonRows.find((row) => row.feature === "Request body inspection");
  assert.ok(requestBodyRow);
  assert.equal(requestBodyRow.sockguard, "Planned");
  assert.equal(requestBodyRow.planned, true);

  assert.equal(comparisonRows.at(-1)?.feature, "YAML config");
});
