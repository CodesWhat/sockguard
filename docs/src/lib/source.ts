import type { Page } from "fumadocs-core/source";
import { loader } from "fumadocs-core/source";
import { docs } from "../../.source/server";

export const source = loader(docs.toFumadocsSource(), {
  baseUrl: "/",
});

export type DocsPageData = (typeof docs.docs)[number];

export function getDocsPage(slugs?: string[]) {
  // Fumadocs 16.7.x currently widens loader page data back to base PageData.
  return source.getPage(slugs) as Page<DocsPageData> | undefined;
}
