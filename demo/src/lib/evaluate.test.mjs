import assert from "node:assert/strict";
import test from "node:test";

import { compileRules, evaluate, evaluateCompiled } from "./evaluate.ts";

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

test("double-star segments outside /** expand across path separators", () => {
  const result = evaluate(
    [{ method: "GET", path: "/images**json", action: "allow" }],
    "GET",
    "/images/v1/json",
  );

  assert.deepEqual(result, {
    action: "allow",
    ruleIndex: 0,
    reason: "matched allow rule",
  });
});

test("single-star segments stop at path separators", () => {
  const result = evaluate(
    [{ method: "GET", path: "/containers/*/logs", action: "allow" }],
    "GET",
    "/containers/sockguard/logs",
  );

  assert.deepEqual(result, {
    action: "allow",
    ruleIndex: 0,
    reason: "matched allow rule",
  });
});

test("method mismatches continue scanning and eventually default deny", () => {
  const compiled = compileRules([
    { method: "POST", path: "/_ping", action: "allow" },
  ]);

  assert.deepEqual(evaluateCompiled(compiled, "GET", "/_ping"), {
    action: "deny",
    ruleIndex: -1,
    reason: "no matching allow rule",
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

test("glob escaping caches repeated literal characters during compilation", () => {
  const nativeReplace = String.prototype.replace;
  let escapeCalls = 0;

  String.prototype.replace = function (...args) {
    if (this.length === 1 && args[0] instanceof RegExp && args[1] === "\\$&") {
      escapeCalls++;
    }
    return Reflect.apply(nativeReplace, this, args);
  };

  try {
    compileRules([{ method: "GET", path: "/zzzzzzzzzz", action: "allow" }]);
    assert.equal(escapeCalls, 1);
  } finally {
    String.prototype.replace = nativeReplace;
  }
});

test("glob compilation treats repeated surrogate-pair literals as one character", () => {
  const nativeReplace = String.prototype.replace;
  let emojiEscapeCalls = 0;
  let surrogateHalfEscapeCalls = 0;

  String.prototype.replace = function (...args) {
    if (this === "😀") {
      emojiEscapeCalls++;
    } else if (this === "\uD83D" || this === "\uDE00") {
      surrogateHalfEscapeCalls++;
    }
    return Reflect.apply(nativeReplace, this, args);
  };

  try {
    compileRules([{ method: "GET", path: "/😀😀😀", action: "allow" }]);
    assert.equal(emojiEscapeCalls, 1);
    assert.equal(surrogateHalfEscapeCalls, 0);
  } finally {
    String.prototype.replace = nativeReplace;
  }
});
