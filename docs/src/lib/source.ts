import type { Page } from "fumadocs-core/source";
import { loader } from "fumadocs-core/source";
import { docs } from "../../.source/server";

export const source = loader(docs.toFumadocsSource(), {
  baseUrl: "/",
});

type DocsPageData = (typeof docs.docs)[number];

export function getDocsPage(slugs?: string[]) {
  // Page<Type, Data>: the first generic is the slug type, not the data type.
  // Fumadocs' loader still widens .data back to base PageData without the cast.
  return source.getPage(slugs) as Page<string | undefined, DocsPageData> | undefined;
}
