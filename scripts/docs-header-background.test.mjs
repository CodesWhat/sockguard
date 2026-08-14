import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";

const globalsCss = new URL("../docs/src/app/globals.css", import.meta.url);

test("docs subnav uses the sidebar card background token", async () => {
  const css = await readFile(globalsCss, "utf8");

  assert.match(css, /#nd-subnav\s*\{[^}]*background-color:\s*var\(--color-fd-card\)/s);
});
