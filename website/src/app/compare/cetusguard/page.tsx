import { createComparisonRoute } from "@/lib/comparison-route";
import { getComparisonRouteConfig } from "@/lib/comparison-route-data";

const { metadata, RoutePage } = createComparisonRoute(getComparisonRouteConfig("cetusguard"));

export { metadata };
export default RoutePage;
