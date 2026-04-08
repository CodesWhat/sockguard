import assert from "node:assert/strict";
import test from "node:test";

import { evaluate } from "./evaluate.ts";

test("trailing /** matches the bare path like the Go proxy", () => {
  const result = evaluate(
    [
      { method: "GET", path: "/containers/**", action: "allow" },
      { method: "*", path: "/**", action: "deny", reason: "no matching allow rule" },
    ],
    "GET",
    "/containers",
  );

  assert.deepEqual(result, {
    action: "allow",
    ruleIndex: 0,
    reason: "matched allow rule",
  });
});

test("version-stripped bare paths still match trailing /** rules", () => {
  const result = evaluate(
    [
      { method: "GET", path: "/containers/**", action: "allow" },
      { method: "*", path: "/**", action: "deny", reason: "no matching allow rule" },
    ],
    "GET",
    "/v1.45/containers",
  );

  assert.deepEqual(result, {
    action: "allow",
    ruleIndex: 0,
    reason: "matched allow rule",
  });
});

test("catch-all /** still matches the root path", () => {
  const result = evaluate(
    [{ method: "*", path: "/**", action: "deny", reason: "default deny" }],
    "GET",
    "/",
  );

  assert.deepEqual(result, {
    action: "deny",
    ruleIndex: 0,
    reason: "default deny",
  });
});

test("repeated evaluations reuse compiled regexes for the same rule set", () => {
  const NativeRegExp = globalThis.RegExp;
  let constructions = 0;

  function CountingRegExp(...args) {
    constructions++;
    return Reflect.construct(NativeRegExp, args, new.target ?? NativeRegExp);
  }

  Object.setPrototypeOf(CountingRegExp, NativeRegExp);
  CountingRegExp.prototype = NativeRegExp.prototype;

  globalThis.RegExp = CountingRegExp;

  try {
    const rules = [
      { method: "GET", path: "/containers/**", action: "allow" },
      { method: "*", path: "/**", action: "deny", reason: "default deny" },
    ];

    evaluate(rules, "GET", "/images/json");
    evaluate(rules, "GET", "/networks/json");

    assert.equal(constructions, rules.length);
  } finally {
    globalThis.RegExp = NativeRegExp;
  }
});
