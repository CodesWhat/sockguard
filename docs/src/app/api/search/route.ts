import { createFromSource } from "fumadocs-core/search/server";
import { source } from "@/lib/source";

// Static export: the index is built once at `next build` and served as JSON
// from /docs/api/search, then queried in the browser by the search dialog.
export const revalidate = false;

export const { staticGET: GET } = createFromSource(source);
