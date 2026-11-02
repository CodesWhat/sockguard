import { Fragment } from "react";

// Renders `backtick` spans in plain data strings as <code>.
export function InlineCode({ text }: { text: string }) {
  const parts = text.split("`");
  return (
    <>
      {parts.map((part, i) => {
        const key = `${i}-${part.slice(0, 12)}`;
        return i % 2 === 1 ? <code key={key}>{part}</code> : <Fragment key={key}>{part}</Fragment>;
      })}
    </>
  );
}
