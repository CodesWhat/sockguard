import type { IconName } from "@/components/icon";
import type { ComparisonRouteConfig } from "@/lib/comparison-route";

export type ComparisonRouteRawConfig = Omit<
  ComparisonRouteConfig,
  "comparisonData" | "highlights"
> & {
  comparisonTable: string;
  highlightsTable: string;
  highlightIconMap: Record<string, IconName>;
};
