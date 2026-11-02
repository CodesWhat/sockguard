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
import { Icon } from "@/components/icon";
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
};

const TOOLS: Tool[] = [
  { name: SITE_CONFIG.name, slug: null, key: "sockguard" },
  { name: "Tecnativa", slug: "tecnativa", key: "tecnativa" },
  { name: "LinuxServer", slug: "linuxserver", key: "linuxserver" },
  { name: "wollomatic", slug: "wollomatic", key: "wollomatic" },
  { name: "11notes", slug: "11notes", key: "elevenNotes" },
  { name: "CetusGuard", slug: "cetusguard", key: "cetusguard" },
];

const REGION_LABEL = "Sockguard comparison matrix. Scroll sideways to see every column.";

const RIVALS = TOOLS.filter((tool) => tool.key !== "sockguard");

function cellFor(tool: Tool, feature: (typeof MATRIX_FEATURES)[number]): ComparisonCell {
  if (feature.row === null) {
    return PROJECT_HEALTH[tool.key][feature.key as "maintained" | "openSource"];
  }
  return comparisonCell(feature.row, tool.key);
}

function VersionsChecked() {
  return (
    <>
      Versions checked {COMPETITOR_VERSIONS_CHECKED_AT}:{" "}
      {RIVALS.map(
        (tool) =>
          `${tool.name} ${COMPETITOR_VERSIONS[tool.key as keyof typeof COMPETITOR_VERSIONS]}`,
      ).join(" · ")}
      . Re-checked at every release cut.
    </>
  );
}

export function CompareMatrix() {
  return (
    <div className="mx">
      {/* biome-ignore lint/a11y/noNoninteractiveTabindex: a horizontally scrollable region must be keyboard reachable */}
      <section className="scroll" tabIndex={0} aria-label={REGION_LABEL}>
        <table className="cmp mxt">
          <caption className="sr">
            Sockguard compared with {RIVALS.length} alternatives across {MATRIX_FEATURES.length}{" "}
            features
          </caption>
          <thead>
            <tr>
              <th scope="col">Tool</th>
              {MATRIX_FEATURES.map((f) => (
                <th key={f.key} scope="col">
                  {f.label}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {TOOLS.map((tool) => (
              <tr key={tool.name} className={tool.slug ? undefined : "me-r"}>
                <th scope="row">
                  {tool.slug ? (
                    <Link href={`/compare/${tool.slug}`}>
                      {tool.name}
                      <Icon name="arrow-up-right" />
                    </Link>
                  ) : (
                    <span className="selfn">{tool.name}</span>
                  )}
                </th>
                {MATRIX_FEATURES.map((f) => (
                  <td key={f.key}>
                    <ComparisonCellIcon value={cellFor(tool, f)} />
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </section>
      <div className="leg">
        <span className="yes">
          <Icon name="check" />
          Yes
        </span>
        <span className="part">
          <Icon name="minus" />
          Partial
        </span>
        <span className="chip t-danger nocase">
          <Icon name="x" />
          No
        </span>
        <span>· Click a tool for the full breakdown</span>
      </div>
      <div className="leg">
        <VersionsChecked />
      </div>
    </div>
  );
}
