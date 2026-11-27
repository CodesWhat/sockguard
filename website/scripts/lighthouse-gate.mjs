// Lighthouse gate for the static export in out/ (npm run build first).
// Audits the home page and one docs page, prints the category scores, and
// exits non-zero when performance or accessibility drops below the threshold.
// The export is served by e2e/serve.mjs (real vercel.json headers, gzip,
// immutable assets) and audited with Playwright's Chromium, so it runs in the
// same Playwright container as the browser checks with no extra browser.

import { spawn } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "@playwright/test";
import lighthouse from "lighthouse";

export const THRESHOLD = 90;
export const CATEGORIES = ["performance", "accessibility"];
export const PAGES = ["/", "/docs/cis-docker-benchmark"];

const here = dirname(fileURLToPath(import.meta.url));

// Pure: turns Lighthouse category scores (0..1 or null) into a table plus the
// list of failures. A missing score fails, it never passes silently.
export function evaluate(url, categories, threshold = THRESHOLD) {
  const rows = [];
  const failures = [];
  for (const id of CATEGORIES) {
    const raw = categories?.[id]?.score;
    const score = typeof raw === "number" ? Math.round(raw * 100) : null;
    rows.push({ url, category: id, score });
    if (score === null || score < threshold) {
      failures.push(`${url} ${id}: ${score === null ? "no score" : score} (< ${threshold})`);
    }
  }
  return { rows, failures };
}

function topAudits(lhr, categoryId, limit = 5) {
  const refs = lhr.categories?.[categoryId]?.auditRefs ?? [];
  return refs
    .map((ref) => lhr.audits[ref.id])
    .filter((a) => a && a.score !== null && a.score < 0.9 && a.scoreDisplayMode !== "informative")
    .sort((a, b) => a.score - b.score)
    .slice(0, limit)
    .map((a) => `${a.id} (${Math.round(a.score * 100)})`);
}

async function waitForServer(base, attempts = 50) {
  for (let i = 0; i < attempts; i++) {
    try {
      const res = await fetch(base);
      if (res.ok) return;
    } catch {}
    await new Promise((r) => setTimeout(r, 200));
  }
  throw new Error(`static server did not come up at ${base}`);
}

async function main() {
  const port = Number(process.env.LH_PORT ?? 4318);
  const debugPort = Number(process.env.LH_DEBUG_PORT ?? 9333);
  const base = `http://127.0.0.1:${port}`;
  const server = spawn(process.execPath, [resolve(here, "../e2e/serve.mjs")], {
    env: { ...process.env, E2E_PORT: String(port) },
    stdio: "ignore",
  });
  let browser;
  const failures = [];
  try {
    await waitForServer(base);
    browser = await chromium.launch({
      headless: true,
      executablePath: process.env.CHROME_PATH || undefined,
      args: [`--remote-debugging-port=${debugPort}`, "--no-sandbox"],
    });
    for (const path of PAGES) {
      const url = `${base}${path}`;
      const result = await lighthouse(url, {
        port: debugPort,
        output: "json",
        logLevel: "error",
        onlyCategories: CATEGORIES,
      });
      const { rows, failures: pageFailures } = evaluate(path, result.lhr.categories);
      for (const row of rows) {
        console.log(
          `${row.category.padEnd(14)} ${String(row.score ?? "n/a").padStart(3)}  ${row.url}`,
        );
      }
      for (const id of CATEGORIES) {
        const weak = topAudits(result.lhr, id);
        if (weak.length > 0) console.log(`  ${id} weakest: ${weak.join(", ")}`);
      }
      failures.push(...pageFailures);
    }
  } finally {
    await browser?.close();
    server.kill();
  }
  if (failures.length > 0) {
    console.error(`\nLighthouse gate failed (threshold ${THRESHOLD}):`);
    for (const f of failures) console.error(`  ${f}`);
    process.exit(1);
  }
  console.log(`\nLighthouse gate passed (threshold ${THRESHOLD}).`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await main();
}
