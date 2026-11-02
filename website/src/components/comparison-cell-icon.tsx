import { Icon } from "@/components/icon";

export type CellValue = "yes" | "partial" | "no";

// A "No" is a danger chip carrying the word, not a grey X: a missing
// capability is the point of the matrix, so it has to read at a glance and
// not lean on colour alone.
export function ComparisonCellIcon({ value }: { value: CellValue }) {
  if (value === "no") {
    return (
      <span className="chip t-danger nocase">
        <Icon name="x" />
        No
      </span>
    );
  }
  if (value === "partial") {
    return (
      <span className="part">
        <Icon name="minus" />
        <span className="sr">Partial</span>
      </span>
    );
  }
  return (
    <span className="yes">
      <Icon name="check" />
      <span className="sr">Yes</span>
    </span>
  );
}
