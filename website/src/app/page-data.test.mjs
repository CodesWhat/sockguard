import assert from "node:assert/strict";
import test from "node:test";

import { comparisonRows } from "./data/comparison-rows.ts";
import { features } from "./data/features.ts";
import { faqItems } from "./data/faq.ts";
import { roadmap } from "../lib/site-content.ts";

test("website features live in extracted data modules", () => {
  assert.equal(features.length, 19);
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
      "Container Image Trust",
      "Visibility-Controlled Reads",
      "Named Client Profiles",
      "Rate Limits & Concurrency Caps",
      "Per-Profile Rollout Modes",
      "Hot-Reload + Admin API",
      "Remote Upstreams & Failover",
    ],
  );
  assert.deepEqual(
    [...new Set(features.map((feature) => feature.category))].sort(),
    ["control", "operations", "security"],
  );
});

test("website comparison rows live in extracted data modules", () => {
  assert.equal(comparisonRows.length, 19);

  const requestBodyRow = comparisonRows.find((row) => row.feature === "Request body inspection");
  assert.ok(requestBodyRow);
  assert.equal(
    requestBodyRow.sockguard,
    "Yes (container, exec, image, build, volume, network, secret, config, service, swarm, node, plugin)",
  );
  assert.notEqual(requestBodyRow.planned, true);
  assert.equal(requestBodyRow.wollomatic, "Partial (bind-mount restrictions)");

  const perClientRow = comparisonRows.find((row) => row.feature === "Per-client policies");
  assert.ok(perClientRow);
  assert.equal(perClientRow.sockguard, "CIDR + labels + cert selectors incl. SPKI + unix peer");
  assert.equal(perClientRow.wollomatic, "Partial (IP/hostname + labels)");

  assert.ok(comparisonRows.find((row) => row.feature === "Resource owner labels"));
  assert.ok(comparisonRows.find((row) => row.feature === "Remote TCP mTLS (listener)"));
  assert.ok(comparisonRows.find((row) => row.feature === "Remote daemon upstream (TLS)"));
  assert.ok(comparisonRows.find((row) => row.feature === "Read-side visibility / redaction"));
  assert.ok(comparisonRows.find((row) => row.feature === "Structured access logs"));
  assert.ok(comparisonRows.find((row) => row.feature === "Dedicated audit log schema"));
  assert.ok(comparisonRows.find((row) => row.feature === "Prometheus metrics"));
  assert.ok(comparisonRows.find((row) => row.feature === "Active upstream watchdog"));
  assert.ok(comparisonRows.find((row) => row.feature === "Trace/log correlation"));
  assert.ok(comparisonRows.find((row) => row.feature === "Rate limits / concurrency caps"));
  assert.ok(comparisonRows.find((row) => row.feature === "Rollout modes (enforce / warn / audit)"));
  assert.ok(comparisonRows.find((row) => row.feature === "Signed policy bundles"));
  assert.ok(comparisonRows.find((row) => row.feature === "Container image trust"));
  assert.ok(comparisonRows.find((row) => row.feature === "Hot-reload + admin API"));

  assert.equal(comparisonRows.at(-1)?.feature, "Hot-reload + admin API");
});

test("roadmap data is valid and matches expected milestones", () => {
  assert.ok(roadmap.length > 0, "roadmap must be non-empty");

  // Latest released milestone must be v1.4.0 (v1.4.0/v1.4.1 shipped 2026-07-10)
  const releasedMilestones = roadmap.filter((m) => m.status === "released");
  assert.ok(releasedMilestones.length > 0, "must have at least one released milestone");
  const latestReleased = releasedMilestones[releasedMilestones.length - 1];
  assert.equal(latestReleased.version, "v1.4.0", "latest released milestone must be v1.4.0");
  assert.equal(latestReleased.status, "released");

  // Must reference the current in-progress milestone v1.5.0
  const v150 = roadmap.find((m) => m.version === "v1.5.0");
  assert.ok(v150, "roadmap must include a v1.5.0 milestone");

  // Every milestone must have a non-empty items array
  for (const milestone of roadmap) {
    assert.ok(
      Array.isArray(milestone.items) && milestone.items.length > 0,
      `milestone ${milestone.version} must have non-empty items array`,
    );
  }
});

test("faqItems data is valid", () => {
  assert.ok(Array.isArray(faqItems), "faqItems must be an array");
  assert.ok(faqItems.length >= 5, "faqItems must have at least 5 items");

  for (const item of faqItems) {
    assert.ok(
      typeof item.question === "string" && item.question.length > 0,
      "each faq item must have a non-empty question",
    );
    assert.ok(
      typeof item.answer === "string" && item.answer.length > 0,
      "each faq item must have a non-empty answer",
    );
  }
});
