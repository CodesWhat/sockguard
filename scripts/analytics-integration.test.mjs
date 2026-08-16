import assert from "node:assert/strict";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";

const repoRoot = new URL("..", import.meta.url).pathname;

function source(relativePath) {
  const target = join(repoRoot, relativePath);
  return existsSync(target) ? readFileSync(target, "utf8") : "";
}

function walk(directory) {
  const files = [];
  if (!existsSync(directory)) return files;
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const target = join(directory, entry.name);
    if (entry.isDirectory()) files.push(...walk(target));
    else if (entry.isFile()) files.push(target);
  }
  return files;
}

test("PostHog replaces Vercel telemetry at one exact version in both build roots", () => {
  for (const workspace of ["website", "docs"]) {
    const packageJson = JSON.parse(source(`${workspace}/package.json`));
    assert.equal(packageJson.dependencies["posthog-js"], "1.417.0");
    assert.equal(packageJson.dependencies["@vercel/analytics"], undefined);
    assert.equal(packageJson.dependencies["@vercel/speed-insights"], undefined);
  }
});

test("route generation is a checked build and development prerequisite", () => {
  const rootScripts = JSON.parse(source("package.json")).scripts;
  assert.equal(rootScripts["sync:analytics-routes"], "node scripts/analytics-routes.mjs");
  assert.equal(rootScripts["check:analytics-routes"], "node scripts/analytics-routes.mjs --check");

  for (const workspace of ["website", "docs"]) {
    const scripts = JSON.parse(source(`${workspace}/package.json`)).scripts;
    assert.match(scripts.build, /^node \.\.\/scripts\/analytics-routes\.mjs --check && /u);
    assert.match(scripts.dev, /^node \.\.\/scripts\/analytics-routes\.mjs --check && /u);
  }
});

test("both build roots use the same privacy runtime and initialize only from instrumentation-client", () => {
  for (const relativePath of [
    "src/lib/analytics-contract.ts",
    "src/lib/analytics-client.ts",
    "src/lib/analytics.ts",
  ]) {
    assert.equal(source(`docs/${relativePath}`), source(`website/${relativePath}`));
  }

  for (const workspace of ["website", "docs"]) {
    const instrumentation = source(`${workspace}/src/instrumentation-client.ts`);
    const analytics = source(`${workspace}/src/lib/analytics.ts`);
    const sourceFiles = walk(join(repoRoot, workspace, "src")).filter((file) =>
      /\.(?:ts|tsx)$/u.test(file),
    );
    const initCallers = sourceFiles.filter((file) =>
      /\binitializeAnalytics\(\)/u.test(readFileSync(file, "utf8")),
    );

    assert.match(instrumentation, /void initializeAnalytics\(\)/u);
    assert.deepEqual(
      initCallers.map((file) => file.slice(join(repoRoot, workspace).length + 1)),
      ["src/instrumentation-client.ts"],
    );
    assert.match(analytics, /import\("posthog-js"\)/u);
    assert.match(analytics, /getOrCreateAnalyticsRuntime/u);
    assert.match(analytics, /process\.env\.NEXT_PUBLIC_POSTHOG_PROJECT_TOKEN/u);
    assert.match(analytics, /process\.env\.NEXT_PUBLIC_POSTHOG_HOST/u);
    assert.match(analytics, /process\.env\.NEXT_PUBLIC_POSTHOG_UI_HOST/u);
  }
});

test("committed pathname changes emit one pageview through both shared layouts", () => {
  for (const workspace of ["website", "docs"]) {
    const component = source(`${workspace}/src/components/analytics-pageview.tsx`);
    const layout = source(`${workspace}/src/app/layout.tsx`);

    assert.match(component, /usePathname\(\)/u);
    assert.match(component, /useEffect/u);
    assert.match(component, /lastPathname/u);
    assert.match(
      component,
      workspace === "docs"
        ? /capturePageview\(toPublicDocsPathname\(pathname\)\)/u
        : /capturePageview\(pathname\)/u,
    );
    assert.match(layout, /<AnalyticsPageview\s*\/>/u);
    assert.doesNotMatch(layout, /@vercel\/analytics|@vercel\/speed-insights/u);
  }
});

test("tracked links validate explicit CTA ids and placements at activation time", () => {
  const websiteLink = source("website/src/components/tracked-link.tsx");
  const docsAnchor = source("docs/src/components/tracked-anchor.tsx");

  assert.match(websiteLink, /usePathname\(\)/u);
  assert.match(websiteLink, /captureCta\(pathname, ctaId, placement\)/u);
  assert.match(docsAnchor, /usePathname\(\)/u);
  assert.match(docsAnchor, /captureCta\(toPublicDocsPathname\(pathname\), ctaId, placement\)/u);
  for (const component of [websiteLink, docsAnchor]) {
    assert.match(component, /data-analytics-cta/u);
    assert.match(component, /data-analytics-placement/u);
  }
});

test("the cookieless envelope keeps the fields PostHog's server hash requires", () => {
  const contract = source("website/src/lib/analytics-contract.ts");

  // PostHog's cookieless server-hash ingestion step reads $raw_user_agent and
  // $host straight off event.properties and drops the event — with a
  // cookieless_missing_user_agent / cookieless_missing_host ingestion warning
  // and zero rows ingested — if either is absent. posthog-js attaches both by
  // default; before_send must require and forward them, not silently strip
  // them. Regression guard: if these keys ever disappear from before_send (or
  // the comment explaining why they're there), every cookieless event on
  // Sockguard drops with no PostHog-side error beyond the ingestion warning.
  assert.match(contract, /\$raw_user_agent/u);
  assert.match(contract, /\$host/u);
  assert.match(contract, /cookieless_missing_user_agent|cookieless server-hash/u);
});

test("all approved Sockguard marketing CTA families have exact annotations", () => {
  const header = source("website/src/components/site-header.tsx");
  const buttons = source("website/src/components/cta-buttons.tsx");
  const page = source("website/src/app/page.tsx");
  const comparison = source("website/src/components/comparison-page.tsx");
  const getStarted = source("website/src/components/get-started.tsx");
  const footer = source("website/src/components/footer.tsx");
  const starHistory = source("website/src/components/star-history.tsx");

  assert.match(header, /ctaId="docs_root"\s+placement="header"/u);
  assert.match(header, /ctaId="github_repository"\s+placement="header"/u);
  assert.match(buttons, /placement: "hero" \| "comparison"/u);
  assert.match(buttons, /ctaId="github_repository"\s+placement=\{placement\}/u);
  assert.match(buttons, /ctaId="docs_root"\s+placement=\{placement\}/u);
  assert.match(page, /<CtaButtons[^>]*placement="hero"/u);
  assert.match(comparison, /<CtaButtons[^>]*placement="comparison"/u);
  assert.match(getStarted, /captureCta\(pathname, `install_\$\{id\}`, "get_started"\)/u);
  assert.match(getStarted, /ctaId="docs_root"\s+placement="get_started"/u);
  assert.match(footer, /ctaId: "docs_root"/u);
  assert.match(footer, /ctaId: "github_repository"/u);
  assert.match(footer, /ctaId="community_discord"\s+placement="footer"/u);
  assert.match(starHistory, /ctaId="github_repository"\s+placement="star_history"/u);
});

test("all approved Sockguard docs CTA families have exact annotations", () => {
  const header = source("docs/src/components/site-header.tsx");
  const footer = source("docs/src/components/footer.tsx");

  assert.match(header, /ctaId="docs_root"\s+placement="header"/u);
  assert.match(header, /ctaId="github_repository"\s+placement="header"/u);
  assert.match(footer, /ctaId: "docs_root"/u);
  assert.match(footer, /ctaId: "github_repository"/u);
  assert.doesNotMatch(footer, /community_discord/u);
});
