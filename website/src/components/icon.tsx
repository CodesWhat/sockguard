// Phosphor icons, served as one SVG sprite from /public/icons/phosphor.svg.
export type IconName =
  | "arrow-right"
  | "arrows-clockwise"
  | "book-open"
  | "chart-bar"
  | "check"
  | "clock"
  | "discord-logo"
  | "eye"
  | "file-code"
  | "fingerprint"
  | "flask"
  | "git-branch"
  | "github-logo"
  | "hard-drives"
  | "heart"
  | "lifebuoy"
  | "lightning"
  | "list"
  | "lock"
  | "magnifying-glass"
  | "minus"
  | "moon"
  | "package"
  | "plugs-connected"
  | "shield-check"
  | "shield-warning"
  | "sliders-horizontal"
  | "star"
  | "sun"
  | "terminal-window"
  | "users-three"
  | "warning"
  | "x";

export function Icon({ name, className }: { name: IconName; className?: string }) {
  return (
    <svg className={className ? `ic ${className}` : "ic"} aria-hidden="true" focusable="false">
      <use href={`/icons/phosphor.svg#ph-${name}`} />
    </svg>
  );
}
