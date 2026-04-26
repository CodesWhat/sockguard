import assert from "node:assert/strict";
import test from "node:test";

import { comparisonRows } from "./data/comparison-rows.ts";
import { features } from "./data/features.ts";

test("website features live in extracted data modules", () => {
  assert.equal(features.length, 12);
  assert.deepEqual(
    features.map((feature) => feature.title),
    [
      "Default-Deny Posture",
      "Request Body Inspection",
      "mTLS for Remote TCP",
      "Owner Label Isolation",
      "Client ACL Primitives",
      "Granular Control",
      "Structured Access Logging",
      "YAML Configuration",
      "Tecnativa Compatible",
      "Minimal Attack Surface",
      "Visibility-Controlled Reads",
      "Named Client Profiles",
    ],
  );
  assert.deepEqual(
    [...new Set(features.map((feature) => feature.category))].sort(),
    ["control", "operations", "security"],
  );
});

test("website comparison rows live in extracted data modules", () => {
  assert.equal(comparisonRows.length, 10);

  const requestBodyRow = comparisonRows.find((row) => row.feature === "Request body inspection");
  assert.ok(requestBodyRow);
  assert.equal(
    requestBodyRow.sockguard,
    "Yes (create, exec, volume, secret, config, service, swarm, plugin, pull, build)",
  );
  assert.notEqual(requestBodyRow.planned, true);
  assert.equal(requestBodyRow.wollomatic, "Partial (bind-mount restrictions)");

  const perClientRow = comparisonRows.find((row) => row.feature === "Per-client policies");
  assert.ok(perClientRow);
  assert.equal(perClientRow.sockguard, "CIDR + labels + cert selectors + unix peer");
  assert.equal(perClientRow.wollomatic, "IP/hostname + labels");

  assert.ok(comparisonRows.find((row) => row.feature === "Resource owner labels"));
  assert.ok(comparisonRows.find((row) => row.feature === "Remote TCP mTLS"));
  assert.ok(comparisonRows.find((row) => row.feature === "Read-side visibility / redaction"));
  assert.ok(comparisonRows.find((row) => row.feature === "Structured access logs"));
  assert.ok(comparisonRows.find((row) => row.feature === "Dedicated audit log schema"));

  assert.equal(comparisonRows.at(-1)?.feature, "YAML config");
});
