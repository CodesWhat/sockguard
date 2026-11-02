// Point-in-time numbers for the hero proof band. These are a snapshot, not
// live-fetched: refresh them when cutting a release.
export const PROOF_SNAPSHOT = {
  checkedAt: "2026-11-01",
  stars: "15",
  forks: "2",
  // Docker Hub pull_count for codeswhat/sockguard, 25,450 on the date above.
  pulls: "25K",
} as const;

// "5 alternatives compared": Tecnativa, LinuxServer, wollomatic, 11notes, CetusGuard.
export const ALTERNATIVES_COMPARED = 5;
// The CI statement-coverage floor, also stated in the FAQ.
export const COVERAGE_FLOOR = "96%+";
