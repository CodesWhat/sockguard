import assert from "node:assert/strict";
import test from "node:test";
import { SITE_CONFIG } from "../lib/site-config.ts";
import { roadmap } from "../lib/site-content.ts";
import { comparisonRows } from "./data/comparison-rows.ts";
import { faqItems } from "./data/faq.ts";
import { features } from "./data/features.ts";

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
  assert.deepEqual([...new Set(features.map((feature) => feature.category))].sort(), [
    "control",
    "operations",
    "security",
  ]);
});

test("website comparison rows live in extracted data modules", () => {
  assert.equal(comparisonRows.length, 21);

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

  const podmanRow = comparisonRows.find((row) => row.feature === "Podman native libpod API");
  assert.ok(podmanRow);
  assert.equal(podmanRow.linuxserver, "Yes");
  assert.equal(podmanRow.cetusguard, "Yes");
  assert.equal(podmanRow.sockguard, "Yes (default-deny /libpod coverage incl. pod lifecycle)");
  assert.notEqual(podmanRow.planned, true);

  const listenerRow = comparisonRows.find((row) => row.feature === "Multiple main listeners");
  assert.ok(listenerRow);
  assert.equal(listenerRow.cetusguard, "Yes");
  assert.equal(listenerRow.sockguard, "Yes (Unix and/or TCP, listener-scoped TLS + profiles)");
  assert.notEqual(listenerRow.planned, true);

  assert.ok(comparisonRows.find((row) => row.feature === "Hot-reload + admin API"));

  assert.equal(comparisonRows.at(-1)?.feature, "Hot-reload + admin API");
});

test("roadmap data is valid and matches expected milestones", () => {
  assert.ok(roadmap.length > 0, "roadmap must be non-empty");

  // v2.0.0 whole-app hardening release.
  const releasedMilestones = roadmap.filter((m) => m.status === "released");
  assert.ok(releasedMilestones.length > 0, "must have at least one released milestone");
  const latestReleased = releasedMilestones[releasedMilestones.length - 1];
  assert.equal(latestReleased.version, "v2.0.0", "latest released milestone must be v2.0.0");
  assert.equal(latestReleased.status, "released");

  // Must retain the previous stable milestones.
  const v150 = roadmap.find((m) => m.version === "v1.5.0");
  assert.ok(v150, "roadmap must include a v1.5.0 milestone");
  assert.equal(v150.status, "released", "v1.5.0 must be released");

  const v151 = roadmap.find((m) => m.version === "v1.5.1");
  assert.ok(v151, "roadmap must include a v1.5.1 milestone");
  assert.equal(v151.status, "released", "v1.5.1 must be released");

  const v152 = roadmap.find((m) => m.version === "v1.5.2");
  assert.ok(v152, "roadmap must include a v1.5.2 milestone");
  assert.equal(v152.status, "released", "v1.5.2 must be released");

  const nextMilestones = roadmap.filter((m) => m.status === "next");
  assert.equal(nextMilestones.length, 1, "roadmap must have exactly one next milestone");
  assert.equal(nextMilestones[0].version, "v2.1.0", "v2.1.0 must be the next milestone");

  const v210 = roadmap.find((m) => m.version === "v2.1.0");
  assert.ok(v210, "roadmap must retain the RUN-instruction work as v2.1.0");
  assert.equal(v210.status, "next", "v2.1.0 must become next after v2.0.0 ships");
  assert.ok(
    v210.items.every((item) => !item.includes("#185")),
    "v2.1.0 must not present closed issue #185 as the owner of planned work",
  );

  assert.ok(
    latestReleased.items.some(
      (item) =>
        item.includes("archives and checksums use sigstore bundles") &&
        item.includes("images are signed and verified by digest"),
    ),
    "v2.0.0 must distinguish blob bundles from registry image signatures",
  );

  // Every milestone must have a non-empty items array
  for (const milestone of roadmap) {
    assert.ok(
      Array.isArray(milestone.items) && milestone.items.length > 0,
      `milestone ${milestone.version} must have non-empty items array`,
    );
  }
});

test("CLI demo keeps release-specific provenance explicitly illustrative", () => {
  assert.deepEqual(SITE_CONFIG.cliDemo, {
    commit: "<sha>",
    built: "<rfc3339>",
    goVersion: "go1.26.6",
    logTime: "<rfc3339>",
  });
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
