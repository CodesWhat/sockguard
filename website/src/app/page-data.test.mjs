import assert from "node:assert/strict";
import test from "node:test";

import { comparisonRows } from "./data/comparison-rows.ts";
import { features } from "./data/features.ts";

test("website features live in extracted data modules", () => {
  assert.equal(features.length, 10);
  assert.deepEqual(
    features.map((feature) => feature.title),
    [
      "Default-Deny Posture",
      "Request Body Inspection",
      "mTLS for Remote TCP",
      "Owner Label Isolation",
      "Client ACL Primitives",
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
  assert.equal(comparisonRows.length, 9);

  const requestBodyRow = comparisonRows.find((row) => row.feature === "Request body inspection");
  assert.ok(requestBodyRow);
  assert.equal(requestBodyRow.sockguard, "Yes (/containers/create)");
  assert.notEqual(requestBodyRow.planned, true);

  const perClientRow = comparisonRows.find((row) => row.feature === "Per-client policies");
  assert.ok(perClientRow);
  assert.equal(perClientRow.sockguard, "CIDR + labels");

  assert.ok(comparisonRows.find((row) => row.feature === "Resource owner labels"));
  assert.ok(comparisonRows.find((row) => row.feature === "Remote TCP mTLS"));

  assert.equal(comparisonRows.at(-1)?.feature, "YAML config");
});
