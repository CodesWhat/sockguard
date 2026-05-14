import assert from "node:assert/strict";
import test from "node:test";

import { comparisonRows } from "./data/comparison-rows.ts";
import { features } from "./data/features.ts";

test("website features live in extracted data modules", () => {
  assert.equal(features.length, 17);
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
      "Operator Observability",
      "YAML Configuration",
      "Tecnativa Compatible",
      "Minimal Attack Surface",
      "Signed Policy Bundles",
      "Visibility-Controlled Reads",
      "Named Client Profiles",
      "Rate Limits & Concurrency Caps",
      "Per-Profile Rollout Modes",
      "Hot-Reload + Admin API",
    ],
  );
  assert.deepEqual(
    [...new Set(features.map((feature) => feature.category))].sort(),
    ["control", "operations", "security"],
  );
});

test("website comparison rows live in extracted data modules", () => {
  assert.equal(comparisonRows.length, 17);

  const requestBodyRow = comparisonRows.find((row) => row.feature === "Request body inspection");
  assert.ok(requestBodyRow);
  assert.equal(
    requestBodyRow.sockguard,
    "Yes (container, image, build, volume, network, secret, config, service, swarm, node, plugin)",
  );
  assert.notEqual(requestBodyRow.planned, true);
  assert.equal(requestBodyRow.wollomatic, "Partial (bind-mount restrictions)");

  const perClientRow = comparisonRows.find((row) => row.feature === "Per-client policies");
  assert.ok(perClientRow);
  assert.equal(perClientRow.sockguard, "CIDR + labels + cert selectors incl. SPKI + unix peer");
  assert.equal(perClientRow.wollomatic, "IP/hostname + labels");

  assert.ok(comparisonRows.find((row) => row.feature === "Resource owner labels"));
  assert.ok(comparisonRows.find((row) => row.feature === "Remote TCP mTLS"));
  assert.ok(comparisonRows.find((row) => row.feature === "Read-side visibility / redaction"));
  assert.ok(comparisonRows.find((row) => row.feature === "Structured access logs"));
  assert.ok(comparisonRows.find((row) => row.feature === "Dedicated audit log schema"));
  assert.ok(comparisonRows.find((row) => row.feature === "Prometheus metrics"));
  assert.ok(comparisonRows.find((row) => row.feature === "Active upstream watchdog"));
  assert.ok(comparisonRows.find((row) => row.feature === "Trace/log correlation"));
  assert.ok(comparisonRows.find((row) => row.feature === "Rate limits / concurrency caps"));
  assert.ok(comparisonRows.find((row) => row.feature === "Rollout modes (enforce / warn / audit)"));
  assert.ok(comparisonRows.find((row) => row.feature === "Signed policy bundles"));
  assert.ok(comparisonRows.find((row) => row.feature === "Hot-reload + admin API"));

  assert.equal(comparisonRows.at(-1)?.feature, "Hot-reload + admin API");
});
