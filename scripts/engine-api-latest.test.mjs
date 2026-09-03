import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(scriptDir, "..");
const scriptPath = resolve(scriptDir, "engine-api-latest.sh");

function heading(id, text) {
  return `<h2 class="scroll-mt-20 flex items-center gap-2" id=${id}><a class="text-black dark:text-white no-underline hover:underline" href=#${id}>${text}</a></h2><ul><li>x</li></ul>`;
}

function run(html) {
  return spawnSync("bash", [scriptPath], {
    cwd: repoRoot,
    input: html,
    encoding: "utf8",
  });
}

describe("engine-api-latest.sh", () => {
  it("prints the newest recognized heading, ignoring inlined SVG/stray version-shaped noise", () => {
    const html =
      "<html><body>" +
      heading("v155-api-changes", "v1.55 API changes") +
      heading("v154-api-changes", "v1.54 API changes") +
      heading("v153-api-changes", "v1.53 API changes") +
      '<svg><path d="M v1.875 0 0"/></svg><p>v1.999</p>' +
      "</body></html>";

    const result = run(html);

    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stdout, "1.55\n");
  });

  it("fails closed when the newest heading is reworded away from 'API changes'", () => {
    const html =
      heading("v155-api-changes", "v1.55 API changes") +
      heading("v156-api-changes", "v1.56 API updates");

    const result = run(html);

    assert.equal(result.status, 1);
    assert.equal(result.stdout, "");
    assert.match(result.stderr, /v1\.56 API updates/);
  });

  it("fails closed when the newest heading is recased", () => {
    const html =
      heading("v155-api-changes", "v1.55 API changes") +
      heading("v156-api-changes", "V1.56 API changes");

    const result = run(html);

    assert.equal(result.status, 1);
    assert.equal(result.stdout, "");
  });

  it("fails when no version heading is found at all", () => {
    const result = run("<p>nothing here</p>");

    assert.equal(result.status, 1);
    assert.equal(result.stdout, "");
    assert.match(result.stderr, /no version heading found/);
  });

  it("fails on an implausible triple-digit minor", () => {
    const result = run(heading("v1125-api-changes", "v1.125 API changes"));

    assert.equal(result.status, 1);
    assert.equal(result.stdout, "");
    assert.match(result.stderr, /implausible/);
  });

  it("picks the numeric max among recognized headings regardless of document order", () => {
    const html =
      heading("v154-api-changes", "v1.54 API changes") +
      heading("v155-api-changes", "v1.55 API changes");

    const result = run(html);

    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stdout, "1.55\n");
  });
});
