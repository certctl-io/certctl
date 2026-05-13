# Git history normalization — 2026-05-13

> Last reviewed: 2026-05-13

This page documents a one-time normalization of certctl's git history
that landed on `master` on 2026-05-13. If you are reading this because
your clone failed to fast-forward, or because a commit SHA you bookmarked
no longer resolves, this is the explanation.

## What changed

Every commit's `author` and `committer` metadata was rewritten to a
single canonical identity (`shankar0123 <skreddy040@gmail.com>`). The
14 pre-rewrite author identities — operator name variants plus
AI/automation identities (Claude, Copilot, cowork agent, certctl-bot,
etc.) — collapsed to that one canonical author.

No source-code content was changed by the rewrite. Every line of code
in every commit is byte-for-byte identical to its pre-rewrite version.
Only the `author` and `committer` metadata fields were touched; commit
messages, subject lines, milestone IDs (M49, L-1, etc.), and every
other line of every commit's body are preserved verbatim.

## Why

Two reasons:

1. **LLC ownership transfer.** The codebase is now legally owned by
   **certctl LLC**, which the operator incorporated to hold rights in
   the project. The BSL 1.1 Licensor field in `LICENSE` flipped from a
   natural-person name to `certctl LLC` in the same change set. Uniform
   per-commit authorship under one canonical operator identity makes
   the chain of title between the codebase and the LLC unambiguous.

2. **Pre-traction cleanup.** The rewrite cost of git-history
   normalization scales with how many external clones and references
   have calcified against specific commit SHAs. Doing it now, before
   the project has a large external surface, minimizes disruption to
   downstream consumers.

## What is preserved

A complete off-platform bundle backup of the pre-rewrite tree is held
by the operator (off-repo, not pushed). It contains every original
commit SHA, every original author identity, and the full ref graph as
it existed before the rewrite. The bundle is the immutable
preservation record and is recoverable forever.

An `archive/pre-author-normalization-2026-05-13` tag briefly existed
on origin pointing at the pre-rewrite tip but was removed when the
operator opted to clean the contributor graph of pre-rewrite
authorship signal. The bundle remains as the canonical archive — any
forensic question about pre-rewrite state can be answered by loading
the bundle into a fresh clone (`git clone pre-rewrite-2026-05-13.bundle`).

## Recovering after the rewrite

If you had a clone of certctl from before 2026-05-13, your local
history diverged from origin's at the rewrite. Easiest recovery:

```bash
cd certctl
git fetch origin
git fetch origin --tags
git reset --hard origin/master
```

This force-aligns your local tree with the new origin. Any local
branches you had based on pre-rewrite history will need rebasing onto
the new master.

If you need to inspect the pre-rewrite state for a forensic or
diligence question, contact the operator directly — the off-platform
bundle is the canonical archive and is available on request.

## Container images and release tarballs

ghcr.io container images that were published before the rewrite
(`ghcr.io/certctl-io/certctl-{server,agent}:<old-tag>`) remain pullable
indefinitely. Their OCI source-SHA labels reference commit SHAs that
no longer resolve in the public origin — the images themselves still
work; only the source-SHA back-reference is now orphan. New release
images published after the rewrite reference current SHAs normally.

If you downloaded a release tarball before the rewrite, the tarball's
contents are unchanged; only its associated `git` SHA differs from the
current `v2.x.y` tag (which has been re-pointed to the rewritten
commit at the same logical point in history).

## Operational note for contributors

Future contributions to certctl should be authored under the
operator's canonical git identity. Pull requests from external
contributors will need a Contributor License Agreement (CLA) workflow,
which the project will set up before accepting external PRs. Until
then, the project does not solicit or accept external code
contributions.
