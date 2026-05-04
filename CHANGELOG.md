# Changelog

## v2.0.68 — Image registry path changed ⚠️

> **Image registry path changed.** Starting this release, container images publish to `ghcr.io/certctl-io/certctl-server` and `ghcr.io/certctl-io/certctl-agent`. Existing pulls from `ghcr.io/shankar0123/certctl-{server,agent}:<tag>` continue to work for previously-published tags (the registry never deletes images), but the `:latest` tag at the old path stops moving forward at this release. Update your `docker pull` paths, `docker-compose.yml` `image:` keys, or Helm `image.repository` values to receive future updates. Old `git clone` / `git push` / install-script / API URLs continue to redirect forever — only the container-registry path changed.

This is the only operator-action-required change in v2.0.68. Other changes in this release are cosmetic URL refreshes after the GitHub-org transfer from `shankar0123/certctl` to `certctl-io/certctl` (HTTP redirects mean no other operator action is required) plus an internal contextcheck lint fix in the agent. Full commit list is on the [GitHub release page](https://github.com/certctl-io/certctl/releases/tag/v2.0.68).

---

certctl no longer maintains a hand-edited per-version changelog. Per-release
notes are auto-generated from commit messages between consecutive tags.

**Where to find what changed in a given release:**

- **[GitHub Releases](https://github.com/certctl-io/certctl/releases)** — every
  tag has an auto-generated "What's Changed" section pulled from the commits
  between that tag and the previous one, plus per-release supply-chain
  verification instructions (Cosign / SLSA / SBOM).
- **`git log <prev-tag>..<this-tag> --oneline`** — same content, locally.

**Why no hand-edited CHANGELOG.md:**

certctl is solo-developed and pushes directly to master. Maintaining a
hand-edited CHANGELOG meant the file drifted (entries piled into
`[unreleased]` and never got promoted to per-version sections when tags were
cut). A stale CHANGELOG is worse than no CHANGELOG — it signals abandoned
maintenance to security-conscious operators doing diligence.

The auto-generated release notes work here because commit messages follow a
descriptive convention: `<area>: <summary>` with a longer body for non-trivial
changes (see `git log v2.0.50..HEAD` for the established pattern). Anyone
reading the GitHub Releases page can see exactly what landed in each version
without depending on the author to manually update a separate file.

**For the historical record:** earlier versions (pre-v2.2.0 and the [2.2.0]
tag itself) had a hand-edited CHANGELOG. That content is preserved in
[git history](https://github.com/certctl-io/certctl/blob/v2.2.0/CHANGELOG.md)
at the v2.2.0 tag.
