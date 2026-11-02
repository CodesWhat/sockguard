import { BASE_PATH } from "@/lib/site-config";

// Phosphor icons, served as one SVG sprite from /public/icons/phosphor.svg.
export type IconName =
  | "arrow-right"
  | "arrows-clockwise"
  | "book-open"
  | "discord-logo"
  | "github-logo"
  | "list"
  | "magnifying-glass"
  | "moon"
  | "sun";

export function Icon({ name, className }: { name: IconName; className?: string }) {
  return (
    <svg className={className ? `ic ${className}` : "ic"} aria-hidden="true" focusable="false">
      <use href={`${BASE_PATH}/icons/phosphor.svg#ph-${name}`} />
    </svg>
  );
}
