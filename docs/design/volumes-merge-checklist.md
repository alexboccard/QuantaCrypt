# Volumes Feature — Merge Checklist

**Status as of 2026-04-20:** All implementation work was completed 2026-03-17.
The branch has been uncommitted for 6 weeks and flagged by 6 consecutive
weekly audits. This checklist exists so the merge can be finished in one
sitting without re-deriving context.

## Why this is blocked
- Volumes feature is fully implemented, tested (97% coverage on core modules),
  and integrated into the UI.
- All code lives in the working tree as uncommitted + untracked files.
- No technical blocker remains — the merge is an operational task.

## Files to commit

**Modified (10):**
- `.gitignore`
- `README.md`
- `pyproject.toml`
- `scripts/build.py`
- `src/quantacrypt/__main__.py`
- `src/quantacrypt/ui/launcher.py`
- `tests/conftest.py`
- `tests/test_crypto.py`
- `tests/test_gui_logic.py`
- `tests/test_integration.py`

**New files:**
- `docs/design/encrypted-volumes.md` (design doc)
- `docs/design/volumes-merge-checklist.md` (this file — delete after merge if not wanted)
- `src/quantacrypt/assets/vol_icon.png`
- `src/quantacrypt/core/fuse_ops.py`
- `src/quantacrypt/core/volume.py`
- `src/quantacrypt/ui/volume_manager.py`
- `tests/test_volume.py`

**To delete locally before commit (sandbox cannot remove them):**
- `weekly-audit-2026-03-23.md`
- `weekly-audit-2026-03-30.md`

## Pre-merge sanity checks

1. `python -m pytest --tb=short -q` — expect 351 passed, 73 skipped, 0 failed, coverage ≥ 95%.
2. `git diff --stat` to confirm the expected ~10 modified files.
3. `git status` to confirm untracked files match the list above.

## Commit strategy

Single commit on a feature branch, then PR to `master`:

```bash
# Create feature branch from current working tree
git checkout -b feat/encrypted-volumes

# Remove orphaned audit files first
rm weekly-audit-2026-03-23.md weekly-audit-2026-03-30.md

# Stage everything relevant
git add .gitignore README.md pyproject.toml scripts/build.py \
        src/quantacrypt/ tests/ docs/

# Commit
git commit -m "feat: add encrypted volumes (.qcv) with FUSE-mountable containers"

# Push + open PR
git push -u origin feat/encrypted-volumes
gh pr create --fill
```

## Post-merge

- [ ] Update `RELEASING.md` with any volumes-specific release steps
  (FUSE dependency note, new icon asset, etc.)
- [ ] Tag a release — version is already bumped to 1.2.0 in `pyproject.toml`
- [ ] Close related tasks in `Profile/TASKS.md`
- [ ] Remove the "EMERGENCY" flag from `CLAUDE.md` Active Projects table

## Post-mortem (if curious)

The 6-week drift happened because the feature was implemented in parallel
with other polish work, the branch was never pushed, and subsequent weekly
audits kept adding context instead of forcing the merge. The lesson for
similar features: push an open draft PR the day a feature is "functionally
done," even before tests and polish land. That converts "uncommitted work"
into reviewable state and breaks the audit-only feedback loop.
