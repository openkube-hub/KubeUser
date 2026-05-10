# Governance

This document defines the governance model for the **KubeUser** project
(`github.com/openkube-hub/KubeUser`).

---

## Table of Contents

- [Roles](#roles)
- [Becoming a Maintainer](#becoming-a-maintainer)
- [Maintainer Responsibilities](#maintainer-responsibilities)
- [Emeritus Maintainers](#emeritus-maintainers)
- [Decision Making](#decision-making)
- [Formal Votes](#formal-votes)
- [API Versioning Policy](#api-versioning-policy)
- [Release Process](#release-process)
- [Amendments](#amendments)

---

## Roles

| Role | Description |
|------|-------------|
| **Contributor** | Anyone who opens an issue, submits a PR, participates in discussions, or improves documentation. No formal appointment required. |
| **Maintainer** | Trusted contributors with merge rights and release authority. Listed in [MAINTAINERS.md](./MAINTAINERS.md). |
| **Emeritus Maintainer** | Former maintainers who have stepped back. Recognized for past contributions; no active duties or merge rights. |

---

## Becoming a Maintainer

Any contributor may be nominated — including self-nomination. The bar is sustained,
meaningful contribution rather than volume alone.

**Criteria:**

- At least **3 significant merged pull requests** (features, bug fixes, refactors, or
  substantial documentation improvements — not typo fixes)
- At least **3 months of active participation** in the project
- Demonstrated familiarity with the codebase, architecture, and project values

**Process:**

1. Open a PR adding the nominee to [MAINTAINERS.md](./MAINTAINERS.md) with a brief summary
   of their contributions.
2. Existing maintainers are notified. A **7 business-day lazy consensus window** opens.
3. If no maintainer objects, the PR is merged and the nominee is onboarded.
4. If an objection is raised, a [formal vote](#formal-votes) is held instead.

---

## Maintainer Responsibilities

Active maintainers are expected to:

- Review and merge (or close with explanation) pull requests within a reasonable time.
- Triage new issues and label them appropriately.
- Participate in release planning and cut releases when ready.
- Uphold the [Code of Conduct](./CODE_OF_CONDUCT.md) and enforce it when needed.
- Communicate absences that last longer than **4 weeks**.

---

## Emeritus Maintainers

A maintainer who is no longer able to actively participate may request emeritus status,
or the active maintainers may propose it after **6 months of inactivity**.

- Emeritus maintainers are listed in [MAINTAINERS.md](./MAINTAINERS.md) under a separate section.
- They retain no merge rights but may be consulted for their institutional knowledge.
- Emeritus maintainers may return to active status by re-engaging and going through the
  standard nomination process.

---

## Decision Making

This project uses **lazy consensus** for day-to-day decisions:

- A proposal (PR, issue, or discussion post) is considered **accepted** if no maintainer
  objects within **5 business days**.
- Any maintainer may call for a [formal vote](#formal-votes) on any proposal at any time.
- Minor changes (documentation fixes, test improvements, dependency bumps) may be merged
  immediately by any maintainer after at least one approval.

---

## Formal Votes

The following decisions **always** require a formal vote among active maintainers:

- Adding or removing a maintainer (when lazy consensus fails)
- Major architectural changes (e.g., moving from CRD-backed to Aggregated API)
- Changing the project license
- Archiving or sunsetting the project
- Applying to or graduating within CNCF

**Voting rules:**

- Each active maintainer gets one vote: **+1** (approve), **0** (abstain), **-1** (block).
- A **-1** must include a written rationale and a proposal to resolve the concern.
- Decisions pass with a **simple majority** of non-abstaining votes.
- Votes are held in a GitHub issue or PR and remain open for **7 calendar days**.
- Results are recorded in the relevant issue/PR for transparency.

---

## API Versioning Policy

| API Version | Stability | Upgrade Path |
|-------------|-----------|--------------|
| `v1alpha1` | Experimental. Breaking changes allowed with a deprecation notice in the release notes. | Manual migration required. |
| `v1beta1` | Stable field semantics. No removals without a two-release deprecation period. | Automated migration via conversion webhook planned. |
| `v1` | GA. No breaking changes. Additive changes only. | Fully backward compatible. |

**Promotion criteria:**

- `v1alpha1 → v1beta1`: No known breaking issues from real-world usage; at least two
  independent adopters reported.
- `v1beta1 → v1`: API has been stable for at least two minor releases; conversion webhook
  implemented and tested; conformance test suite passing.

---

## Release Process

1. **Versioning**: This project follows [Semantic Versioning](https://semver.org/)
   (`MAJOR.MINOR.PATCH`). While the API remains `v1alpha1`, the minor version increments
   on any breaking API or behavior change.

2. **Release notes**: Every release tag must include a GitHub Release with:
   - A summary of new features, bug fixes, and breaking changes.
   - Upgrade notes if any manual steps are required.
   - Known issues.

3. **Artifacts**: The container image is published to
   `ghcr.io/openkube-hub/kubeuser-controller:<tag>`.

4. **Artifact signing**: Release images and Helm charts are signed with
   [cosign](https://github.com/sigstore/cosign) using keyless signing (Sigstore).
   Verification instructions are included in the release notes.

5. **Helm chart**: The Helm chart version in `helm/kubeuser/Chart.yaml` is updated to
   match the operator version on every release.

---

## Amendments

Changes to this document require a [formal vote](#formal-votes) by the active maintainers.
