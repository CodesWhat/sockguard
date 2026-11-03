import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { test } from "node:test";

// The star chart is Star History's hosted /chart embed (ops rule X55). Earlier
// hosted options failed silently at HTTP 200 (#303), so this contract pins the
// exact embed forms. It cannot prove the remote image renders: that is checked
// by eye, signed out.

const repoRoot = resolve(import.meta.dirname, "..");
const readme = readFileSync(resolve(repoRoot, "README.md"), "utf8");
const component = readFileSync(
  resolve(repoRoot, "website/src/components/star-history.tsx"),
  "utf8",
);

const CHART =
  "https://api.star-history.com/chart?repos=codeswhat/sockguard&type=date&legend=top-left";
const PAGE = "https://www.star-history.com/?type=date&repos=CodesWhat%2Fsockguard";

test("the README embeds Star History through one contiguous <picture> block", () => {
  // <picture>, never a bare <img>, so GitHub's theme toggle picks the chart.
  // One pattern over the whole block so the pieces cannot drift apart.
  const escaped = (s) => s.replaceAll(/[.*+?^${}()|[\]\\]/gu, "\\$&");
  assert.match(
    readme,
    new RegExp(
      `<a href="${escaped(PAGE)}">\\s*<picture>\\s*` +
        `<source media="\\(prefers-color-scheme: dark\\)" srcset="${escaped(CHART)}&theme=dark">\\s*` +
        `<source media="\\(prefers-color-scheme: light\\)" srcset="${escaped(CHART)}">\\s*` +
        `<img alt="Star History chart for CodesWhat/sockguard" src="${escaped(CHART)}"[^>]*>\\s*` +
        `</picture>\\s*</a>`,
      "u",
    ),
  );
});

test("the website component loads both themes from the same chart and keeps its name", () => {
  assert.ok(
    component.includes(`const CHART =\n  "${CHART}"`) ||
      component.includes(`const CHART = "${CHART}"`),
  );
  assert.match(component, /className="sl"[\s\S]*?src=\{CHART\}/u);
  assert.match(component, /className="sd"[\s\S]*?src=\{`\$\{CHART\}&theme=dark`\}/u);
  assert.match(component, /aria-label="Star history chart for CodesWhat\/sockguard"/u);
  assert.match(component, /ctaId="github_repository"/u);
  assert.match(component, /placement="star_history"/u);
});
