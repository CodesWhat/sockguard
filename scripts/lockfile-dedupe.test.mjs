import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { classify, collectDrift, isIgnoredPostcssOverrideDrift, parseNpmJson } from "./lockfile-dedupe.mjs";

const NEXT_POSTCSS_CHANGE = {
  from: { name: "postcss", version: "8.4.0", path: "/repo/node_modules/next/node_modules/postcss" },
  to: { name: "postcss", version: "8.5.0", path: "/repo/node_modules/next/node_modules/postcss" },
};

const WORKSPACE_POSTCSS_ADD = {
  name: "postcss",
  version: "8.5.0",
  path: "/repo/website/node_modules/postcss",
};

const REAL_CHANGE = {
  from: { name: "framer-motion", version: "12.43.0", path: "/repo/node_modules/framer-motion" },
  to: { name: "framer-motion", version: "13.1.0", path: "/repo/node_modules/framer-motion" },
};

function cleanReport() {
  return { add: [], remove: [], change: [] };
}

describe("classify", () => {
  it("reports stale-install when the install report has entries, even if dedupe also has entries", () => {
    const installReport = { add: [], remove: [], change: [REAL_CHANGE] };
    const dedupeReport = { add: [], remove: [], change: [REAL_CHANGE] };

    const result = classify({ installReport, dedupeReport });

    assert.equal(result.kind, "stale-install");
    assert.deepEqual(result.entries, [REAL_CHANGE]);
  });

  it("reports lockfile-drift only when install is clean and dedupe is dirty", () => {
    const installReport = cleanReport();
    const dedupeReport = { add: [], remove: [], change: [REAL_CHANGE] };

    const result = classify({ installReport, dedupeReport });

    assert.equal(result.kind, "lockfile-drift");
    assert.deepEqual(result.entries, [REAL_CHANGE]);
  });

  it("reports ok when both reports are clean", () => {
    const result = classify({ installReport: cleanReport(), dedupeReport: cleanReport() });

    assert.deepEqual(result, { kind: "ok", entries: [] });
  });

  it("suppresses the postcss allowance in the dedupe report", () => {
    const installReport = cleanReport();
    const dedupeReport = {
      add: [WORKSPACE_POSTCSS_ADD],
      remove: [],
      change: [NEXT_POSTCSS_CHANGE],
    };

    const result = classify({ installReport, dedupeReport });

    assert.deepEqual(result, { kind: "ok", entries: [] });
  });

  it("does not apply the postcss allowance to the install report", () => {
    const installReport = { add: [WORKSPACE_POSTCSS_ADD], remove: [], change: [NEXT_POSTCSS_CHANGE] };
    const dedupeReport = cleanReport();

    const result = classify({ installReport, dedupeReport });

    assert.equal(result.kind, "stale-install");
    assert.deepEqual(result.entries, [WORKSPACE_POSTCSS_ADD, NEXT_POSTCSS_CHANGE]);
  });
});

describe("collectDrift", () => {
  it("flattens add, remove, and change entries", () => {
    const report = { add: [REAL_CHANGE.to], remove: [REAL_CHANGE.from], change: [REAL_CHANGE] };

    const drift = collectDrift(report, { ignorePostcss: false });

    assert.deepEqual(drift, [REAL_CHANGE.to, REAL_CHANGE.from, REAL_CHANGE]);
  });

  it("tolerates a report missing add/remove/change keys", () => {
    assert.deepEqual(collectDrift({}, { ignorePostcss: false }), []);
  });
});

describe("isIgnoredPostcssOverrideDrift", () => {
  it("ignores the Next-vendored postcss override change", () => {
    assert.equal(isIgnoredPostcssOverrideDrift(NEXT_POSTCSS_CHANGE), true);
  });

  it("ignores a workspace postcss hoist add/remove entry", () => {
    assert.equal(isIgnoredPostcssOverrideDrift(WORKSPACE_POSTCSS_ADD), true);
  });

  it("does not ignore an unrelated package change", () => {
    assert.equal(isIgnoredPostcssOverrideDrift(REAL_CHANGE), false);
  });
});

describe("parseNpmJson", () => {
  it("strips leading npm lifecycle noise before the first {", () => {
    const raw = "npm warn deprecated foo@1.0.0\n" + '{"add":[],"remove":[],"change":[]}';

    assert.deepEqual(parseNpmJson(raw), { add: [], remove: [], change: [] });
  });

  it("throws on output with no JSON object", () => {
    assert.throws(() => parseNpmJson("npm error something exploded"), /no JSON output/);
  });

  it("throws on output with malformed JSON after the first {", () => {
    assert.throws(() => parseNpmJson("noise { not: valid json"), /malformed JSON/);
  });
});
