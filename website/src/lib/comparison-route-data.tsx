import type { ComparisonRouteConfig } from "@/lib/comparison-route";
import { highlightsFromPipeTable, rowsFromPipeTable } from "@/lib/comparison-route";
import type { ComparisonRouteRawConfig } from "@/lib/comparison-route-data/types";
import { elevenNotesComparisonRouteData } from "./comparison-route-data/11notes";
import { cetusguardComparisonRouteData } from "./comparison-route-data/cetusguard";
import { linuxserverComparisonRouteData } from "./comparison-route-data/linuxserver";
import { tecnativaComparisonRouteData } from "./comparison-route-data/tecnativa";
import { wollomaticComparisonRouteData } from "./comparison-route-data/wollomatic";

const comparisonRouteDataBySlug = {
  tecnativa: tecnativaComparisonRouteData,
  linuxserver: linuxserverComparisonRouteData,
  wollomatic: wollomaticComparisonRouteData,
  "11notes": elevenNotesComparisonRouteData,
  cetusguard: cetusguardComparisonRouteData,
} satisfies Record<string, ComparisonRouteRawConfig>;

export type ComparisonRouteSlug = keyof typeof comparisonRouteDataBySlug;

function resolveComparisonRouteConfig(routeData: ComparisonRouteRawConfig): ComparisonRouteConfig {
  const { comparisonTable, highlightsTable, highlightIconMap, ...config } = routeData;

  return {
    ...config,
    comparisonData: rowsFromPipeTable(comparisonTable),
    highlights: highlightsFromPipeTable(highlightsTable, highlightIconMap),
  };
}

export function getComparisonRouteConfig(slug: ComparisonRouteSlug): ComparisonRouteConfig;
export function getComparisonRouteConfig(slug: string): ComparisonRouteConfig | undefined;
export function getComparisonRouteConfig(slug: string): ComparisonRouteConfig | undefined {
  const routeData = comparisonRouteDataBySlug[slug as ComparisonRouteSlug];
  if (!routeData) {
    return undefined;
  }

  return resolveComparisonRouteConfig(routeData);
}

export function getComparisonRouteSlugs(): ComparisonRouteSlug[] {
  return Object.keys(comparisonRouteDataBySlug) as ComparisonRouteSlug[];
}
