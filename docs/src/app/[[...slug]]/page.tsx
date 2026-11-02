import defaultMdxComponents from "fumadocs-ui/mdx";
import { DocsBody, DocsDescription, DocsPage, DocsTitle, EditOnGitHub } from "fumadocs-ui/page";
import { notFound } from "next/navigation";
import { BASE_URL, GITHUB_URL, SITE_CONFIG } from "@/lib/site-config";
import { getDocsPage, source } from "@/lib/source";

export default async function Page(props: { params: Promise<{ slug?: string[] }> }) {
  const params = await props.params;
  const page = getDocsPage(params.slug);
  if (!page) notFound();

  const MDX = page.data.body;

  return (
    <DocsPage
      toc={page.data.toc}
      full={page.data.full}
      footer={{
        children: (
          <EditOnGitHub
            className="edit"
            href={`${GITHUB_URL}/edit/main/docs/content/docs/${page.path}`}
          />
        ),
      }}
    >
      <DocsTitle>{page.data.title}</DocsTitle>
      <DocsDescription className="desc">{page.data.description}</DocsDescription>
      <DocsBody>
        <MDX components={defaultMdxComponents} />
      </DocsBody>
    </DocsPage>
  );
}

export function generateStaticParams() {
  return source.generateParams();
}

export async function generateMetadata(props: { params: Promise<{ slug?: string[] }> }) {
  const params = await props.params;
  const page = getDocsPage(params.slug);
  if (!page) notFound();

  const slugPath = params.slug?.join("/") ?? "";
  const canonical = slugPath ? `${BASE_URL}/docs/${slugPath}` : `${BASE_URL}/docs`;

  const title = `${page.data.title} | ${SITE_CONFIG.docsTitleSuffix}`;

  return {
    title: { absolute: title },
    description: page.data.description,
    alternates: {
      canonical,
    },
    openGraph: {
      type: "article" as const,
      title,
      description: page.data.description,
      url: canonical,
      siteName: SITE_CONFIG.name,
      images: [{ url: SITE_CONFIG.ogImage, width: 1200, height: 630 }],
    },
    twitter: {
      card: "summary_large_image" as const,
      title,
      description: page.data.description,
      images: [SITE_CONFIG.ogImage],
    },
  };
}
