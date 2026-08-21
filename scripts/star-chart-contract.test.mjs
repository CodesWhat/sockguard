import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { test } from "node:test";

// The star chart is a committed first-party SVG pair (#303). Both previous
// options — star-history.com and the Warpchart embed — failed silently at
// HTTP 200, so this contract pins the replacement and keeps the retired
// hosts from coming back, same pattern as the Go Report Card removal (#283).

const repoRoot = resolve(import.meta.dirname, "..");
const readmePath = resolve(repoRoot, "README.md");
const componentPath = resolve(repoRoot, "website/src/components/star-history.tsx");
const lightSvgPath = resolve(repoRoot, "website/public/star-history.svg");
const darkSvgPath = resolve(repoRoot, "website/public/star-history-dark.svg");

test("the committed star-history SVG pair exists, both or neither", () => {
  // A README <picture> that gained a light chart and kept a stale or missing
  // dark one shows two different histories depending on who is looking.
  assert.ok(existsSync(lightSvgPath), "website/public/star-history.svg must be committed");
  assert.ok(existsSync(darkSvgPath), "website/public/star-history-dark.svg must be committed");
});

test("the README references the committed pair through a <picture> element", () => {
  const readme = readFileSync(readmePath, "utf8");

  // <picture>, never <img>: a media query inside an <img>-embedded SVG
  // resolves against the OS preference, not GitHub's theme toggle.
  assert.match(readme, /<picture>/u);
  assert.match(
    readme,
    /<source media="\(prefers-color-scheme: dark\)" srcset="website\/public\/star-history-dark\.svg">/u,
  );
  assert.match(readme, /<img [^>]*src="website\/public\/star-history\.svg"/u);
});

test("no surface reaches for a retired star-chart host", () => {
  for (const path of [readmePath, componentPath]) {
    const source = readFileSync(path, "utf8");
    assert.doesNotMatch(
      source,
      /(?:warpchart\.dev|star-history\.com)/u,
      `${path} must not reference a retired star-chart host`,
    );
  }
});
