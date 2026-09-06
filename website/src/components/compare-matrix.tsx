import { ArrowUpRight, Check, Minus, X } from "lucide-react";
import Link from "next/link";
import {
  COMPETITOR_VERSIONS,
  COMPETITOR_VERSIONS_CHECKED_AT,
  type ComparisonCell,
  type ComparisonTool,
  comparisonCell,
  MATRIX_FEATURES,
  PROJECT_HEALTH,
} from "@/app/data/comparison-rows";
import { ComparisonCellIcon } from "@/components/comparison-cell-icon";
import { SITE_CONFIG } from "@/lib/site-config";

// Full comparison matrix for /compare. Each competitor row links to its
// dedicated deep-dive page. Every policy cell is derived from
// comparison-rows.ts, which is also what the per-competitor pages in
// lib/comparison-route-data/ restate, so the matrix cannot contradict the page
// it links to.

type Tool = {
  name: string;
  slug: string | null;
  key: ComparisonTool;
  highlight?: boolean;
};

const TOOLS: Tool[] = [
  { name: SITE_CONFIG.name, slug: null, key: "sockguard", highlight: true },
  { name: "Tecnativa", slug: "tecnativa", key: "tecnativa" },
  { name: "LinuxServer", slug: "linuxserver", key: "linuxserver" },
  { name: "wollomatic", slug: "wollomatic", key: "wollomatic" },
  { name: "11notes", slug: "11notes", key: "elevenNotes" },
  { name: "CetusGuard", slug: "cetusguard", key: "cetusguard" },
];

function cellFor(tool: Tool, feature: (typeof MATRIX_FEATURES)[number]): ComparisonCell {
  if (feature.row === null) {
    return PROJECT_HEALTH[tool.key][feature.key as "maintained" | "openSource"];
  }
  return comparisonCell(feature.row, tool.key);
}

export function CompareMatrix() {
  return (
    <div className="overflow-hidden rounded-xl border border-neutral-200 bg-white/50 backdrop-blur-sm dark:border-neutral-800 dark:bg-neutral-900/50">
      <div className="overflow-x-auto">
        <table className="w-full min-w-[860px] text-sm">
          <thead>
            <tr className="border-b border-neutral-200 dark:border-neutral-800">
              <th className="px-4 py-3 text-left font-medium text-neutral-500 dark:text-neutral-400">
                Tool
              </th>
              {MATRIX_FEATURES.map((f) => (
                <th
                  key={f.key}
                  className="whitespace-nowrap px-3 py-3 text-center text-xs font-medium text-neutral-500 dark:text-neutral-400"
                >
                  {f.label}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {TOOLS.map((tool) => (
              <tr
                key={tool.name}
                className={[
                  "border-b border-neutral-100 last:border-0 dark:border-neutral-800/60",
                  tool.highlight ? "bg-amber-500/5" : "",
                ].join(" ")}
              >
                <th scope="row" className="whitespace-nowrap px-4 py-3 text-left font-normal">
                  {tool.slug ? (
                    <Link
                      href={`/compare/${tool.slug}`}
                      className="group inline-flex items-center gap-1.5 font-medium text-neutral-700 transition-colors hover:text-neutral-900 dark:text-neutral-300 dark:hover:text-neutral-100"
                    >
                      {tool.name}
                      <ArrowUpRight className="h-3.5 w-3.5 text-neutral-400 transition-transform group-hover:-translate-y-0.5 group-hover:translate-x-0.5" />
                    </Link>
                  ) : (
                    <span className="font-semibold text-amber-600 dark:text-amber-400">
                      {tool.name}
                    </span>
                  )}
                </th>
                {MATRIX_FEATURES.map((f) => (
                  <td key={f.key} className="px-3 py-3 text-center">
                    <ComparisonCellIcon value={cellFor(tool, f)} />
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="flex flex-wrap items-center gap-x-3 gap-y-1.5 border-t border-neutral-200 px-4 py-3 text-xs text-neutral-500 dark:border-neutral-800 dark:text-neutral-500">
        <span className="inline-flex items-center gap-1.5">
          <Check className="h-3 w-3 text-amber-500" /> Yes
        </span>
        <span className="inline-flex items-center gap-1.5">
          <Minus className="h-3 w-3 text-orange-400" /> Partial
        </span>
        <span className="inline-flex items-center gap-1.5">
          <X className="h-3 w-3 text-neutral-300 dark:text-neutral-600" /> No
        </span>
        <span className="text-neutral-400 dark:text-neutral-600">
          · Click a tool for the full breakdown
        </span>
      </div>

      <div className="border-t border-neutral-200 px-4 py-3 text-xs text-neutral-400 dark:border-neutral-800 dark:text-neutral-600">
        Versions checked {COMPETITOR_VERSIONS_CHECKED_AT}:{" "}
        {TOOLS.filter((tool) => tool.key !== "sockguard")
          .map(
            (tool) =>
              `${tool.name} ${COMPETITOR_VERSIONS[tool.key as keyof typeof COMPETITOR_VERSIONS]}`,
          )
          .join(" · ")}
        . Re-checked at every release cut.
      </div>
    </div>
  );
}
