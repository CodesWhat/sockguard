import assert from "node:assert/strict";
import test from "node:test";

import { cn } from "./utils.ts";

test("cn preserves truthy classes and drops falsy inputs", () => {
  assert.equal(cn("font-bold", null, undefined, false, "text-sm"), "font-bold text-sm");
});

test("cn prefers the last conflicting Tailwind utility", () => {
  assert.equal(cn("px-2 py-1", "px-4"), "py-1 px-4");
});
