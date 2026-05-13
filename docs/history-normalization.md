# Git history normalization — 2026-05-13

> Last reviewed: 2026-05-13

This page documents a one-time normalization of certctl's git history
that landed on `master` on 2026-05-13. If you are reading this because
your clone failed to fast-forward, or because a commit SHA you bookmarked
no longer resolves, this is the explanation.

## What changed

Every commit's `author` and `committer` metadata was rewritten to a
single canonical identity (`shankar0123 <skreddy040@gmail.com>`). Where
the original author was an AI/automation identity (Claude, Copilot,
cowork agent, certctl-bot, etc.), a `Co-authored-by:` trailer was
appended to the commit message preserving the original identity. The
intent is a uniform single-author authorship layer + preserved
attribution of AI involvement.

No source-code content was changed by the rewrite. Every line of code
in every commit is byte-for-byte identical to its pre-rewrite version.
Only `author` / `committer` metadata and (for ~129 AI-touched commits)
a `Co-authored-by:` trailer line were touched.

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

The exact pre-rewrite history is preserved on origin at the tag
**`archive/pre-author-normalization-2026-05-13`**. If you need to
reference an original commit SHA from before the rewrite — for example
in a blog post, an external citation, or a pre-rewrite release artifact
— check that tag. The tag is immutable; we will not move or delete it.

A separate off-platform bundle backup of the pre-rewrite tree is also
held by the operator (off-repo, not pushed). Both artifacts ensure the
original history is recoverable forever.

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

If you want to inspect the pre-rewrite state for any reason:

```bash
git fetch origin archive/pre-author-normalization-2026-05-13
git checkout archive/pre-author-normalization-2026-05-13
```

## Container images and release tarballs

ghcr.io container images that were published before the rewrite
(`ghcr.io/certctl-io/certctl-{server,agent}:<old-tag>`) remain pullable
indefinitely. Their OCI source-SHA labels reference commit SHAs that
now only resolve via the `archive/` tag — the images themselves still
work; only the source-SHA back-reference points at the archive. New
release images published after the rewrite reference current SHAs
normally.

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
