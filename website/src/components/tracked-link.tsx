"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { type ComponentProps, forwardRef, type MouseEventHandler } from "react";
import { captureCta } from "@/lib/analytics";
import type { AnalyticsCtaId, AnalyticsCtaPlacement } from "@/lib/analytics-contract";

type TrackedLinkProps = Omit<ComponentProps<typeof Link>, "href" | "onClick"> & {
  href: string;
  ctaId: AnalyticsCtaId;
  placement: AnalyticsCtaPlacement;
  onClick?: MouseEventHandler<HTMLAnchorElement>;
};

const isDocsHref = (href: string) => href === "/docs" || href.startsWith("/docs/");

export const TrackedLink = forwardRef<HTMLAnchorElement, TrackedLinkProps>(function TrackedLink(
  { ctaId, placement, onClick, ...props },
  ref,
) {
  const pathname = usePathname();

  const handleClick: MouseEventHandler<HTMLAnchorElement> = (event) => {
    onClick?.(event);
    if (!event.defaultPrevented) captureCta(pathname, ctaId, placement);
  };

  // /docs is a separate static export, so it needs a full page load, not a
  // client-side next/link transition.
  if (isDocsHref(props.href)) {
    const { href, prefetch: _prefetch, replace: _replace, scroll: _scroll, ...rest } = props;
    return (
      <a
        {...rest}
        href={href}
        ref={ref}
        onClick={handleClick}
        data-analytics-cta={ctaId}
        data-analytics-placement={placement}
      />
    );
  }

  return (
    <Link
      {...props}
      ref={ref}
      onClick={handleClick}
      data-analytics-cta={ctaId}
      data-analytics-placement={placement}
    />
  );
});
