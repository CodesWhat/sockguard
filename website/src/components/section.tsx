import type { ReactNode } from "react";

// Section header variants from the mock: a = split (header left), b = compact
// side-by-side, c = centered. `stack` puts the header above the content
// instead of in a left column.
export function Section({
  id,
  variant = "a",
  stack = false,
  eyebrow,
  strikeEyebrow = false,
  title,
  sub,
  children,
}: {
  id: string;
  variant?: "a" | "b" | "c";
  stack?: boolean;
  eyebrow: string;
  strikeEyebrow?: boolean;
  title: string;
  sub: ReactNode;
  children: ReactNode;
}) {
  const header = (
    <div className="sec-h">
      <div className={`eyebrow micro${strikeEyebrow ? " strike" : ""}`}>{eyebrow}</div>
      <h2 className="title" id={`${id}-h`}>
        {title}
      </h2>
      <p className="sub">{sub}</p>
    </div>
  );

  return (
    <section
      className="sec"
      id={id}
      data-sv={variant === "a" ? undefined : variant}
      aria-labelledby={`${id}-h`}
    >
      <div className="wrap">
        {stack ? (
          <>
            {header}
            {children}
          </>
        ) : (
          <div className="split">
            {header}
            <div className="main">{children}</div>
          </div>
        )}
      </div>
    </section>
  );
}
