"use client";

import { usePathname } from "next/navigation";
import { type AnchorHTMLAttributes, forwardRef, type MouseEventHandler } from "react";
import { captureCta } from "@/lib/analytics";
import {
  type AnalyticsCtaId,
  type AnalyticsCtaPlacement,
  toPublicDocsPathname,
} from "@/lib/analytics-contract";

type TrackedAnchorProps = Omit<AnchorHTMLAttributes<HTMLAnchorElement>, "href" | "onClick"> & {
  href: string;
  ctaId: AnalyticsCtaId;
  placement: AnalyticsCtaPlacement;
  onClick?: MouseEventHandler<HTMLAnchorElement>;
};

export const TrackedAnchor = forwardRef<HTMLAnchorElement, TrackedAnchorProps>(
  function TrackedAnchor({ href, ctaId, placement, onClick, ...props }, ref) {
    const pathname = usePathname();

    const handleClick: MouseEventHandler<HTMLAnchorElement> = (event) => {
      onClick?.(event);
      if (!event.defaultPrevented) {
        captureCta(toPublicDocsPathname(pathname), ctaId, placement);
      }
    };

    return (
      <a
        {...props}
        href={href}
        ref={ref}
        onClick={handleClick}
        data-analytics-cta={ctaId}
        data-analytics-placement={placement}
      />
    );
  },
);
