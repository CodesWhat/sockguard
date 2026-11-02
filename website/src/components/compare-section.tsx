import Link from "next/link";
import {
  type ComparisonCell,
  type ComparisonTool,
  comparisonCell,
  TEASER_FEATURES,
} from "@/app/data/comparison-rows";
import { Icon } from "@/components/icon";
import { SITE_CONFIG } from "@/lib/site-config";

// Mini comparison teaser: 6 rows, 3 rivals. Cells derive from
// comparison-rows.ts, the same source /compare uses, so the teaser and the
// full matrix cannot disagree about the same claim.

const TOOLS: { label: string; key: ComparisonTool }[] = [
  { label: SITE_CONFIG.name, key: "sockguard" },
  { label: "Tecnativa", key: "tecnativa" },
  { label: "CetusGuard", key: "cetusguard" },
  { label: "wollomatic", key: "wollomatic" },
];

const CELL: Record<ComparisonCell, { cls: string; icon: "check" | "minus" | "x"; text: string }> = {
  yes: { cls: "yes", icon: "check", text: "Yes" },
  partial: { cls: "part", icon: "minus", text: "Partial" },
  no: { cls: "no", icon: "x", text: "No" },
};

function Cell({ value }: { value: ComparisonCell }) {
  const c = CELL[value];
  return (
    <span className={c.cls}>
      <Icon name={c.icon} />
      <span className="sr">{c.text}</span>
    </span>
  );
}

export function CompareTeaser() {
  return (
    <>
      {/* biome-ignore lint/a11y/noNoninteractiveTabindex: a horizontally scrollable table must be keyboard reachable */}
      <section className="scroll" aria-label="Comparison table" tabIndex={0}>
        <table className="cmp">
          <thead>
            <tr>
              <th scope="col">Feature</th>
              {TOOLS.map((t) => (
                <th key={t.key} scope="col" className={t.key === "sockguard" ? "me" : undefined}>
                  {t.label}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {TEASER_FEATURES.map((row) => (
              <tr key={row.label}>
                <th scope="row">{row.label}</th>
                {TOOLS.map((t) => (
                  <td key={t.key} className={t.key === "sockguard" ? "me" : undefined}>
                    <Cell value={comparisonCell(row.row, t.key)} />
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
        <div className="leg">
          {(["yes", "partial", "no"] as const).map((v) => (
            <span key={v} className={CELL[v].cls}>
              <Icon name={CELL[v].icon} />
              {CELL[v].text}
            </span>
          ))}
        </div>
      </section>
      <div className="more">
        <Link className="btn" href="/compare">
          View all comparisons <Icon name="arrow-right" />
        </Link>
      </div>
    </>
  );
}
