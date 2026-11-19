"use client";

// Fumadocs renders its nav title as a link even when none is set, which leaves
// an empty, unnamed link in the sidebar. The sidebar banner carries the name.
export function NoNavTitle() {
  return null;
}
