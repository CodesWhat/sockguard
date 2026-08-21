import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { test } from "node:test";

// The star chart is a committed first-party SVG pair (#303). Both previous
// options — star-history.com and the Warpchart embed — failed silently at
// HTTP 200, so this contract pins the replacement and keeps the retired
// hosts from coming back, same pattern as the Go Report Card removal (#283).

const repoRoot = resolve(import.meta.dirname, "..");
const readmePath = resolve(repoRoot, "README.md");
const lightSvgPath = resolve(repoRoot, "website/public/star-history.svg");
const darkSvgPath = resolve(repoRoot, "website/public/star-history-dark.svg");

test("the committed star-history SVG pair exists and agrees with itself", () => {
  // Both or neither, and drawn from the same data: a README <picture> whose
  // light and dark charts disagree shows two different histories depending
  // on who is looking, and neither is flagged as wrong.
  assert.ok(existsSync(lightSvgPath), "website/public/star-history.svg must be committed");
  assert.ok(existsSync(darkSvgPath), "website/public/star-history-dark.svg must be committed");

  const meta = (path) => {
    const svg = readFileSync(path, "utf8");
    const title = svg.match(/<title>Star history for ([^<]+) — (\d+) stars<\/title>/u);
    assert.ok(title, `${path} must carry the generator's <title> metadata`);
    return { repo: title[1], stars: title[2] };
  };
  const light = meta(lightSvgPath);
  const dark = meta(darkSvgPath);
  assert.equal(light.repo, "CodesWhat/sockguard");
  assert.equal(dark.repo, light.repo);
  assert.equal(dark.stars, light.stars, "light and dark charts must be from the same refresh");
});

test("the README embeds the pair through one contiguous <picture> block", () => {
  const readme = readFileSync(readmePath, "utf8");

  // <picture>, never <img>: a media query inside an <img>-embedded SVG
  // resolves against the OS preference, not GitHub's theme toggle. One
  // regex over the whole block so the pieces cannot drift apart.
  assert.match(
    readme,
    /<a href="https:\/\/github\.com\/CodesWhat\/sockguard\/stargazers">\s*<picture>\s*<source media="\(prefers-color-scheme: dark\)" srcset="website\/public\/star-history-dark\.svg">\s*<img [^>]*src="website\/public\/star-history\.svg"[^>]*>\s*<\/picture>\s*<\/a>/u,
  );
});

test("no tracked file reaches for a retired star-chart host", () => {
  // Sweep every tracked file, case-insensitively, not a hand-picked list —
  // a retired host reintroduced anywhere is the regression. Excluded:
  // CHANGELOG.md (immutable history records the removal) and this test.
  // Escaped literals in other tests (warpchart\.dev) don't match a
  // strict-dot pattern, so they need no carve-out.
  let hits = "";
  try {
    hits = execFileSync(
      "git",
      [
        "grep",
        "-iIl",
        "-e",
        "warpchart\\.dev",
        "-e",
        "star-history\\.com",
        "--",
        ":!CHANGELOG.md",
        ":!scripts/star-chart-contract.test.mjs",
      ],
      { cwd: repoRoot, encoding: "utf8" },
    );
  } catch (error) {
    // git grep exits 1 on zero matches, which is the passing state.
    assert.equal(error.status, 1, error.stderr || error.message);
  }
  assert.equal(hits, "", `retired star-chart hosts referenced in:\n${hits}`);
});
