#!/usr/bin/env bash
# scripts/ci-guards/doc-rot-detector.sh
#
# Per post-v2.1.0 anti-rot item 5 (Auditable Codebase Bundle).
#
# Walks every *.md under docs/ and parses the "> Last reviewed:
# YYYY-MM-DD" blockquote line (the convention established by the
# 2026-05-04 docs overhaul — every doc carries one). Emits:
#
#   - ::warning:: GitHub annotation (yellow, non-blocking) when a doc
#     is older than 90 days vs HEAD's commit timestamp.
#   - ::error:: GitHub annotation + exit 1 when a doc is older than
#     120 days.
#
# Uses HEAD's commit timestamp (git log -1 --format=%ai HEAD) as "now"
# rather than wall-clock — keeps the guard reproducible on a release
# that's been on a shelf. A 2-year-old commit verified today should
# fail the same docs it failed back then, not new ones.
#
# Allowlist: scripts/ci-guards/doc-rot-detector-exceptions.yaml
# (every entry carries a one-line justification + an expiration date).
# docs/archive/** is allowlisted in bulk by directory; it's
# intentionally frozen historical content and shouldn't keep getting
# reviewed.

set -e

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
EXCEPTIONS_FILE="${REPO_ROOT}/scripts/ci-guards/doc-rot-detector-exceptions.yaml"

WARN_DAYS="${CERTCTL_DOC_ROT_WARN_DAYS:-90}"
FAIL_DAYS="${CERTCTL_DOC_ROT_FAIL_DAYS:-120}"

cd "$REPO_ROOT"

# "Now" = the commit timestamp of HEAD, in YYYY-MM-DD form. Falls back
# to the wall clock if git fails (e.g., guard run outside a repo).
NOW_DATE="$(git -C "$REPO_ROOT" log -1 --format=%cs HEAD 2>/dev/null || date -u +%Y-%m-%d)"

python3 - "$REPO_ROOT" "$EXCEPTIONS_FILE" "$NOW_DATE" "$WARN_DAYS" "$FAIL_DAYS" <<'PY'
import os, sys, datetime, pathlib, re

repo_root = pathlib.Path(sys.argv[1])
exceptions_path = pathlib.Path(sys.argv[2])
now_str = sys.argv[3]
warn_days = int(sys.argv[4])
fail_days = int(sys.argv[5])

try:
    now = datetime.date.fromisoformat(now_str)
except Exception:
    sys.stderr.write(f"could not parse now={now_str!r}\n")
    sys.exit(2)

# Load allowlist. Same tiny YAML reader the other guards use.
allowlist_paths = set()
per_doc = {}
if exceptions_path.exists():
    txt = exceptions_path.read_text()
    cur = None
    for raw in txt.splitlines():
        line = raw.rstrip()
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if line.lstrip().startswith("- path:"):
            cur = {"path": line.split(":", 1)[1].strip().strip('"').strip("'")}
            # entries can be a directory (path ends with /) or a single file
            if cur["path"].endswith("/"):
                allowlist_paths.add(cur["path"])
            else:
                per_doc[cur["path"]] = cur
            continue
        if cur is not None and line.startswith("  "):
            if ":" not in line:
                continue
            k, v = line.split(":", 1)
            cur[k.strip()] = v.strip().strip('"').strip("'")

LAST_REVIEWED_RE = re.compile(r"^>\s*Last reviewed:\s*(\d{4}-\d{2}-\d{2})\s*$", re.MULTILINE)

docs_root = repo_root / "docs"
if not docs_root.exists():
    sys.stderr.write("docs/ not found — nothing to check\n")
    sys.exit(0)

# Collect every doc file.
docs = []
for fp in docs_root.rglob("*.md"):
    rel = fp.relative_to(repo_root).as_posix()
    docs.append((rel, fp))

def is_in_allowlisted_dir(rel: str) -> bool:
    for prefix in allowlist_paths:
        if rel.startswith(prefix):
            return True
    return False

def per_doc_active(rel: str) -> (bool, str):
    if rel not in per_doc:
        return False, ""
    e = per_doc[rel]
    exp = e.get("expires")
    just = e.get("justification", "")
    if not exp:
        return False, "allowlist entry missing 'expires:'"
    try:
        ed = datetime.date.fromisoformat(exp)
    except Exception:
        return False, f"allowlist entry has malformed expires: {exp!r}"
    if ed < now:
        return False, f"allowlist entry expired on {exp}"
    if not just:
        return False, "allowlist entry has no justification"
    return True, f"allowlisted until {exp}: {just}"

warn_rows = []
fail_rows = []
missing_field_rows = []
skipped = 0
total_checked = 0

for rel, fp in sorted(docs):
    if is_in_allowlisted_dir(rel):
        skipped += 1
        continue
    ok, msg = per_doc_active(rel)
    if ok:
        skipped += 1
        continue
    body = fp.read_text(errors="ignore")
    m = LAST_REVIEWED_RE.search(body)
    if not m:
        missing_field_rows.append(rel)
        continue
    try:
        reviewed = datetime.date.fromisoformat(m.group(1))
    except Exception:
        missing_field_rows.append(rel + f" (unparseable date {m.group(1)!r})")
        continue
    total_checked += 1
    age = (now - reviewed).days
    if age >= fail_days:
        fail_rows.append((rel, reviewed.isoformat(), age))
    elif age >= warn_days:
        warn_rows.append((rel, reviewed.isoformat(), age))

print(f"doc-rot-detector — now={now.isoformat()} warn≥{warn_days}d fail≥{fail_days}d")
print(f"  total docs scanned: {len(docs)}, allowlisted: {skipped}, dated: {total_checked}, missing date field: {len(missing_field_rows)}")
print()

if missing_field_rows:
    print("::warning::Docs missing or unparseable '> Last reviewed: YYYY-MM-DD' line:")
    for r in missing_field_rows:
        print(f"  - {r}")
    print()
    print("  Add the convention line near the top of each doc, e.g.:")
    print('    > Last reviewed: 2026-MM-DD')

if warn_rows:
    print(f"::warning::Docs older than {warn_days} days (heads-up, non-blocking):")
    for rel, d, age in warn_rows:
        print(f"  - {rel}: reviewed {d} ({age}d ago)")
    print()

if fail_rows:
    print(f"::error::Docs older than {fail_days} days (build-blocking):")
    for rel, d, age in fail_rows:
        print(f"  - {rel}: reviewed {d} ({age}d ago)")
    print()
    print("  Fix options:")
    print("    1. Re-read the doc against the repo, fix any drift, bump '> Last reviewed:' to today.")
    print("    2. If the doc is intentionally frozen, move it under docs/archive/ (allowlisted in bulk).")
    print(f"    3. Add a per-doc allowlist row to {exceptions_path.relative_to(repo_root)} with a justification + expiration.")
    sys.exit(1)

# Missing-date-field counts as a hard fail too — the convention is
# load-bearing.
if missing_field_rows:
    sys.exit(1)

print("OK — every doc under docs/ has a recent '> Last reviewed:' date.")
PY
