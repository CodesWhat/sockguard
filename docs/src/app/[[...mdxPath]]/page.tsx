import { generateStaticParamsFor, importPage } from "nextra/pages";
import { useMDXComponents } from "../../../mdx-components";

export const generateStaticParams = generateStaticParamsFor("mdxPath");

export async function generateMetadata(props: { params: Promise<{ mdxPath?: string[] }> }) {
  const params = await props.params;
  const { metadata } = await importPage(params.mdxPath);
  return metadata;
}

export default async function Page(props: { params: Promise<{ mdxPath?: string[] }> }) {
  const params = await props.params;
  const result = await importPage(params.mdxPath);
  const { default: MDXContent, toc, metadata } = result;
  // biome-ignore lint/correctness/useHookAtTopLevel: useMDXComponents is not a React hook despite the name — it's a Nextra build-time component accessor
  const { wrapper: Wrapper } = useMDXComponents();
  return (
    <Wrapper toc={toc} metadata={metadata} sourceCode={result.sourceCode}>
      <MDXContent {...props} params={params} />
    </Wrapper>
  );
}
