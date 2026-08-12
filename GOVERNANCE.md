# Sockguard Governance

## Model

Sockguard uses a lead-maintainer model. Design and implementation work is
proposed in public issues and pull requests. The lead maintainer owns project
scope, policy semantics, release readiness, and final decisions when consensus
cannot be reached.

The current project roles are:

| Role | Current assignment | Responsibilities |
| --- | --- | --- |
| Lead maintainer | [`@scttbnsn`](https://github.com/scttbnsn) | Direction, issue triage, security response, release approval, and final technical decisions |
| Continuity maintainer | [`@biggest-littlest`](https://github.com/biggest-littlest) | CodesWhat organization administration, access recovery, and release continuity when the lead maintainer is unavailable |
| Code owners | Accounts listed in [`.github/CODEOWNERS`](.github/CODEOWNERS) | Review owned areas and identify policy, compatibility, and security risks |
| Contributors | Anyone participating through issues or pull requests | Propose, implement, test, document, and review changes |

Roles are based on sustained project work and trust. Maintainer and code-owner
changes are recorded in a public pull request and in GitHub's organization audit
log as applicable.

## Decisions and disputes

Routine changes are decided through pull-request review. Security-policy,
compatibility, and public-interface changes should begin with an issue that
records the problem, alternatives, and migration impact. The project seeks
rough consensus, but the lead maintainer makes the final decision when a timely
choice is required and records the reason publicly.

Private vulnerability reports follow [`SECURITY.md`](SECURITY.md). Conduct
reports follow [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).

## Change and release control

Changes branch from and merge back into `main` through pull requests. CI runs
race-enabled tests, linting, vulnerability analysis, integration tests,
fuzzing, and release checks. Tagged releases are created by repository
workflows and are signed and attested with GitHub Actions OIDC.

## Access continuity

Sockguard is owned by the CodesWhat GitHub organization, which has two owner
accounts: `@scttbnsn` and `@biggest-littlest`. Either owner can administer the
repository, close issues, restore maintainer access, manage Actions and release
environments, and continue the pull-request and release process.

Canonical source, issues, workflows, container images, packages, and release
artifacts are kept in GitHub and GHCR. Keyless Sigstore signing and GitHub
provenance avoid a release-signing key held on one maintainer's workstation.
If one maintainer becomes unavailable, the remaining organization owner can
revoke stale access, update role assignments, merge approved work, and publish
a release within one week.

Project forking remains available under Apache-2.0, but it is not the primary
continuity plan.
