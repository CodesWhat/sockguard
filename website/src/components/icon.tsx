// Phosphor icons, served as one SVG sprite from /public/icons/phosphor.svg.
export type IconName =
  | "arrow-right"
  | "arrow-up-right"
  | "arrows-clockwise"
  | "book-open"
  | "chart-bar"
  | "check"
  | "clock"
  | "clock-counter-clockwise"
  | "discord-logo"
  | "eye"
  | "file-code"
  | "fingerprint"
  | "flask"
  | "git-branch"
  | "github-logo"
  | "hard-drives"
  | "heart"
  | "heartbeat"
  | "key"
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
  | "stack"
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
