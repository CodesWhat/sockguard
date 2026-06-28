// Regenerates src/components/sockguard-dog-art.ts from the real CLI banner art
// at app/internal/banner/dog_color.ans. Run with `node scripts/gen-dog-art.mjs`
// from the website/ workspace whenever the banner art changes.
//
// dog_color.ans is a 24-bit truecolor half-block image (▀ upper-half / ▄
// lower-half / space) emitted by the Go banner. We parse the ANSI SGR state,
// run-length-merge identical adjacent cells per row, and emit a compact data
// module the CliDemo renders cell-by-cell so the web demo matches the terminal.

import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { readFileSync, writeFileSync } from "node:fs";

const HERE = dirname(fileURLToPath(import.meta.url));
const SRC = resolve(HERE, "../../app/internal/banner/dog_color.ans");
const OUT = resolve(HERE, "../src/components/sockguard-dog-art.ts");

const raw = readFileSync(SRC, "utf8").replace(/\n$/, "");
const lines = raw.split("\n");

function hex(r, g, b) {
  const h = (n) => n.toString(16).padStart(2, "0");
  return `#${h(r)}${h(g)}${h(b)}`;
}

const rows = [];
for (let ri = 0; ri < lines.length; ri++) {
  const line = lines[ri];
  let fg = null;
  let bg = null;
  const cells = [];
  let i = 0;
  while (i < line.length) {
    if (line[i] === "\x1b") {
      const m = line.slice(i).match(/^\x1b\[([0-9;]*)m/);
      if (m) {
        const params = m[1].split(";").map((x) => (x === "" ? 0 : Number(x)));
        for (let k = 0; k < params.length; k++) {
          const p = params[k];
          if (p === 0) {
            fg = null;
            bg = null;
          } else if (p === 39) {
            fg = null;
          } else if (p === 49) {
            bg = null;
          } else if (p === 38 && params[k + 1] === 2) {
            fg = hex(params[k + 2], params[k + 3], params[k + 4]);
            k += 4;
          } else if (p === 48 && params[k + 1] === 2) {
            bg = hex(params[k + 2], params[k + 3], params[k + 4]);
            k += 4;
          }
        }
        i += m[0].length;
        continue;
      }
    }
    cells.push({ c: line[i], f: fg, b: bg });
    i++;
  }
  const runs = [];
  for (const cell of cells) {
    const last = runs[runs.length - 1];
    if (last && last.c === cell.c && last.f === cell.f && last.b === cell.b) {
      last.n++;
    } else {
      runs.push({ n: 1, c: cell.c, f: cell.f, b: cell.b });
    }
  }
  rows.push({
    id: `r${ri}`,
    runs: runs.map((r, ci) => ({ id: `r${ri}c${ci}`, n: r.n, c: r.c, f: r.f, b: r.b })),
  });
}

const width = Math.max(...rows.map((r) => r.runs.reduce((a, x) => a + x.n, 0)));

const header = `// AUTO-GENERATED from app/internal/banner/dog_color.ans — do not edit by hand.
// 24-bit truecolor half-block rendering of the sockguard dog logo, the same art
// the real \`sockguard serve\` banner prints on a truecolor terminal. Each run is
// a glyph (▀ upper-half / ▄ lower-half / space) repeated \`n\` times, with a 24-bit
// foreground (f) and background (b) hex, or null for the terminal default.
// Regenerate with scripts/gen-dog-art.mjs if banner/dog_color.ans changes.

export type DogRun = { id: string; n: number; c: string; f: string | null; b: string | null };
export type DogRow = { id: string; runs: DogRun[] };

export const DOG_ART_WIDTH = ${width};
`;

writeFileSync(OUT, `${header}\nexport const DOG_ART: DogRow[] = ${JSON.stringify(rows)};\n`);
console.log(`wrote ${OUT} (rows=${rows.length} width=${width})`);
