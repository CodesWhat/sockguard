import type { ReactNode } from "react";

// Sockguard "ember" palette — warm amber keys + rose values, matching the
// site's brand (drydock's get-started.tsx uses the cool sky/lime twin).
const KEY = "text-amber-300"; // YAML keys
const VAL = "text-rose-300"; // image refs, quoted strings, numbers, booleans
const COM = "text-neutral-600"; // comments
const BASE = "text-neutral-300"; // everything else

function parseValue(v: string): ReactNode {
  if (!v) return null;
  // Quoted strings
  if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'")))
    return <span className={VAL}>{v}</span>;
  // Image refs / paths (contain a slash)
  if (v.includes("/")) return <span className={VAL}>{v}</span>;
  // Numbers
  if (/^\d+$/.test(v)) return <span className={VAL}>{v}</span>;
  // Booleans
  if (v === "true" || v === "false") return <span className={VAL}>{v}</span>;
  return <span className={BASE}>{v}</span>;
}

function renderLine(line: string): ReactNode {
  const m = /^(\s*)(.*)$/.exec(line);
  const ws = m?.[1] ?? "";
  const body = m?.[2] ?? "";

  if (!body) return null;

  // Comment
  if (body.startsWith("#")) {
    return (
      <>
        {ws}
        <span className={COM}>{body}</span>
      </>
    );
  }

  // List item
  if (body.startsWith("- ")) {
    return (
      <>
        {ws}
        <span className={BASE}>
          {"- "}
          {body.slice(2)}
        </span>
      </>
    );
  }

  // Key: value
  const ci = body.indexOf(": ");
  if (ci !== -1) {
    return (
      <>
        {ws}
        <span className={KEY}>{body.slice(0, ci)}</span>
        {": "}
        {parseValue(body.slice(ci + 2))}
      </>
    );
  }

  // Key: (no value — ends with colon)
  if (body.endsWith(":")) {
    return (
      <>
        {ws}
        <span className={KEY}>{body.slice(0, -1)}</span>
        {":"}
      </>
    );
  }

  return <>{line}</>;
}

interface YamlBlockProps {
  /** Raw YAML string to syntax-color. */
  code: string;
  /** className forwarded to the <pre> element. */
  className?: string;
}

/**
 * Dependency-free YAML syntax highlighter.
 * Tokenizes per-line: keys → amber, image/path/number/boolean values → rose,
 * comments → muted, everything else → neutral-300.
 */
export function YamlBlock({ code, className }: YamlBlockProps) {
  const lines = code.split("\n");
  return (
    <pre className={className}>
      {lines.map((line, i) => (
        // biome-ignore lint/suspicious/noArrayIndexKey: lines in a static YAML block are positionally stable
        <span key={i}>
          {renderLine(line)}
          {i < lines.length - 1 && "\n"}
        </span>
      ))}
    </pre>
  );
}
