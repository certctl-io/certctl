#!/usr/bin/env bash
# scripts/ci-guards/complete-path-config-coverage.sh
#
# Per post-v2.1.0 anti-rot item 1 (Auditable Codebase Bundle).
#
# Catches "lying fields" — env vars defined in config.go that the rest
# of the codebase never reads. An operator can flip the env var, the
# server returns the value via /api/v1/config (if surfaced), the docs
# say it works, but no business-logic code actually consumes it. The
# guard fails when any operator-facing env var is undefined or has no
# non-config-package consumer.
#
# The bug class this catches: SCEP MustStaple in 2026-04-29 Phase 5.6 —
# the domain field, IssuanceRequest field, extension generation, and
# byte-exact tests all shipped, but the service layer never read
# profile.MustStaple. Configurable bit existed, behavior never changed.
# This guard would have failed that commit.
#
# Allowlist file: scripts/ci-guards/complete-path-config-coverage-exceptions.yaml
# (every entry carries a one-line justification + an expiration date)

set -e

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
EXCEPTIONS_FILE="${REPO_ROOT}/scripts/ci-guards/complete-path-config-coverage-exceptions.yaml"

python3 - "$REPO_ROOT" "$EXCEPTIONS_FILE" <<'PY'
import os, re, sys, datetime, pathlib

repo_root = pathlib.Path(sys.argv[1])
exceptions_path = pathlib.Path(sys.argv[2])

# -----------------------------------------------------------------------------
# 1. Extract env-var read sites from internal/config/config.go.
# -----------------------------------------------------------------------------
config_path = repo_root / "internal" / "config" / "config.go"
src = config_path.read_text()

# Match getEnv* calls that take a CERTCTL_-prefixed string literal as
# their first argument.
env_re = re.compile(
    r'getEnv(?:Bool|Int|Int64|Duration|Float|StringSlice)?\(\s*"(CERTCTL_[A-Z0-9_]+)"',
)
env_vars = sorted({m.group(1) for m in env_re.finditer(src)})

# -----------------------------------------------------------------------------
# 2. Walk every other Go file + Helm chart + .env templates for a reference.
#    "Reference" = the literal "CERTCTL_NAME" string appears anywhere
#    OUTSIDE internal/config/config.go (or a _test.go file in the same
#    package — those don't count as "production consumers").
# -----------------------------------------------------------------------------
SEARCH_ROOTS = [
    repo_root / "cmd",
    repo_root / "internal",
    repo_root / "deploy",
    repo_root / "migrations",
    repo_root / "scripts",
    repo_root / "docs",
    repo_root / "api",
    repo_root / "Makefile",
    repo_root / "README.md",
    repo_root / "CHANGELOG.md",
]


def is_excluded(path: pathlib.Path) -> bool:
    p = str(path.resolve())
    # Skip internal/config itself + the guard's own exceptions file.
    if "/internal/config/" in p:
        return True
    if path.name == "complete-path-config-coverage.sh":
        return True
    if path.name == "complete-path-config-coverage-exceptions.yaml":
        return True
    if "/.git/" in p or "/node_modules/" in p or "/web/dist/" in p:
        return True
    return False


# Index file contents once for speed (this guard runs on every push).
files_by_path: dict[pathlib.Path, str] = {}
for root in SEARCH_ROOTS:
    if not root.exists():
        continue
    if root.is_file():
        if not is_excluded(root):
            try:
                files_by_path[root] = root.read_text(errors="ignore")
            except Exception:
                pass
        continue
    for fp in root.rglob("*"):
        if not fp.is_file():
            continue
        if is_excluded(fp):
            continue
        # Limit to text-ish file types.
        if fp.suffix not in {
            ".go", ".sh", ".yml", ".yaml", ".sql", ".md",
            ".tmpl", ".tpl", ".env", ".json", ".toml", ".ts", ".tsx",
        } and fp.name not in {"Makefile", "Dockerfile"}:
            continue
        try:
            files_by_path[fp] = fp.read_text(errors="ignore")
        except Exception:
            pass


def consumers_for(env_var: str) -> list[pathlib.Path]:
    hits = []
    needle = env_var
    for fp, txt in files_by_path.items():
        if needle in txt:
            hits.append(fp)
    return hits


# -----------------------------------------------------------------------------
# 3. Load the allowlist.
# -----------------------------------------------------------------------------
# Tiny YAML reader — only the shape we need (a top-level list of objects
# with keys: name, justification, expires). Avoids a PyYAML dependency
# the guard would otherwise carry.
allowlist: dict[str, dict] = {}
if exceptions_path.exists():
    txt = exceptions_path.read_text()
    cur = None
    for raw in txt.splitlines():
        line = raw.rstrip()
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if line.lstrip().startswith("- name:"):
            cur = {"name": line.split(":", 1)[1].strip().strip('"').strip("'")}
            allowlist[cur["name"]] = cur
            continue
        if cur is not None and line.startswith("  "):
            if ":" not in line:
                continue
            k, v = line.split(":", 1)
            cur[k.strip()] = v.strip().strip('"').strip("'")

today = datetime.date.today()


def allowlist_active(env_var: str) -> tuple[bool, str]:
    if env_var not in allowlist:
        return False, ""
    entry = allowlist[env_var]
    exp = entry.get("expires")
    if not exp:
        return False, "allowlist entry has no 'expires:' field"
    try:
        exp_d = datetime.date.fromisoformat(exp)
    except Exception:
        return False, f"allowlist entry has malformed expires: {exp!r}"
    if exp_d < today:
        return False, f"allowlist entry expired on {exp}"
    just = entry.get("justification", "")
    if not just:
        return False, "allowlist entry has no 'justification:' field"
    return True, f"allowlisted until {exp}: {just}"


# -----------------------------------------------------------------------------
# 4. Run the check.
# -----------------------------------------------------------------------------
print(f"complete-path config-coverage guard — scanning {len(env_vars)} env vars across {len(files_by_path)} files")
print()

orphans: list[tuple[str, str]] = []
allowlisted: list[tuple[str, str]] = []

for ev in env_vars:
    consumers = consumers_for(ev)
    if consumers:
        continue
    ok, msg = allowlist_active(ev)
    if ok:
        allowlisted.append((ev, msg))
    else:
        orphans.append((ev, msg or "no consumer found"))

if allowlisted:
    print("Allowlisted (no production consumer; documented contract):")
    for ev, msg in allowlisted:
        print(f"  - {ev}: {msg}")
    print()

if orphans:
    print("::error::Orphan env vars — defined in config.go but no consumer found outside internal/config/:")
    for ev, msg in orphans:
        print(f"  - {ev}: {msg}")
    print()
    print("Fix options:")
    print("  1. Wire the env var to a real consumer (the load-bearing path).")
    print("  2. Remove the env var from internal/config/config.go (was it dead code?).")
    print(f"  3. Add an allowlist row to {exceptions_path.relative_to(repo_root)} with")
    print("     - name: \"CERTCTL_NAME\"")
    print("       justification: \"why this is documented but not consumed by our code\"")
    print("       expires: \"YYYY-MM-DD\"   # required; forces periodic re-review")
    sys.exit(1)

print(f"OK — every CERTCTL_* env var ({len(env_vars)}) has at least one non-config-package consumer.")
PY
