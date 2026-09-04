"""Release plumbing: version stamping, code signing, and workflow invariants.

Everything here covers behaviour that only ever runs on a release, which is
the worst place to discover it is broken: a `sed` that silently matched
nothing and shipped the previous version's number, a `codesign` failure that
was printed and ignored, and the scope of the token the build jobs run with.
"""

from __future__ import annotations

import importlib.util
import os
import re
from types import SimpleNamespace

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS = os.path.join(ROOT, "scripts")
WORKFLOWS = os.path.join(ROOT, ".github", "workflows")


def _load(name: str, path: str):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


stamp_version = _load("qc_stamp_version", os.path.join(SCRIPTS, "stamp_version.py"))
build_script = _load("qc_build_script", os.path.join(SCRIPTS, "build.py"))


# ── scripts/stamp_version.py ──────────────────────────────────────────────

@pytest.fixture
def repo(tmp_path):
    """A miniature checkout carrying the three version-bearing files."""
    (tmp_path / "src" / "quantacrypt").mkdir(parents=True)
    (tmp_path / "macos").mkdir()
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "q"\nversion = "1.3.0"\n', encoding="utf-8")
    (tmp_path / "src" / "quantacrypt" / "__init__.py").write_text(
        '    __version__ = "1.3.0"  # keep in sync with pyproject.toml\n',
        encoding="utf-8")
    (tmp_path / "macos" / "project.yml").write_text(
        '        CFBundleShortVersionString: "1.3.0"\n'
        '        CFBundleVersion: "1"\n', encoding="utf-8")
    return tmp_path


def _texts(repo):
    return (
        (repo / "pyproject.toml").read_text(encoding="utf-8"),
        (repo / "src" / "quantacrypt" / "__init__.py").read_text(encoding="utf-8"),
        (repo / "macos" / "project.yml").read_text(encoding="utf-8"),
    )


def test_stamp_rewrites_every_file(repo):
    assert stamp_version.stamp(str(repo), "1.4.0") == 0
    toml, init, yml = _texts(repo)
    assert 'version = "1.4.0"' in toml
    assert '__version__ = "1.4.0"' in init
    assert 'CFBundleShortVersionString: "1.4.0"' in yml


def test_stamp_preserves_the_comment_and_the_indentation(repo):
    stamp_version.stamp(str(repo), "2.0.0")
    _, init, yml = _texts(repo)
    # sed's greedy `".*"` happened to keep these; a structural rewrite has to
    # keep them on purpose.
    assert init == '    __version__ = "2.0.0"  # keep in sync with pyproject.toml\n'
    assert yml.startswith('        CFBundleShortVersionString: "2.0.0"\n')
    # A neighbouring key with the same shape must not be dragged along.
    assert 'CFBundleVersion: "1"' in yml


def test_stamp_quotes_an_unquoted_yaml_value(repo):
    (repo / "macos" / "project.yml").write_text(
        "        CFBundleShortVersionString: 1.3.0\n", encoding="utf-8")
    assert stamp_version.stamp(str(repo), "1.4.0") == 0
    assert (repo / "macos" / "project.yml").read_text(encoding="utf-8") == \
        '        CFBundleShortVersionString: "1.4.0"\n'


def test_a_target_that_no_longer_matches_fails_and_writes_nothing(repo, capsys):
    """The whole point: `sed` exited 0 here and shipped the old version."""
    (repo / "src" / "quantacrypt" / "__init__.py").write_text(
        '    __version__: str = "1.3.0"\n', encoding="utf-8")
    before = _texts(repo)

    assert stamp_version.stamp(str(repo), "1.4.0") == 1

    assert _texts(repo) == before, "a miss must not half-rewrite the checkout"
    assert "__init__.py" in capsys.readouterr().err


def test_an_ambiguous_file_is_refused(repo, capsys):
    (repo / "pyproject.toml").write_text(
        '[project]\nversion = "1.3.0"\n\n[tool.other]\nversion = "9.9.9"\n',
        encoding="utf-8")
    assert stamp_version.stamp(str(repo), "1.4.0") == 1
    assert "ambiguous" in capsys.readouterr().err


def test_check_reports_a_stale_file_then_passes_once_stamped(repo):
    assert stamp_version.stamp(str(repo), "1.4.0", check=True) == 1
    stamp_version.stamp(str(repo), "1.4.0")
    assert stamp_version.stamp(str(repo), "1.4.0", check=True) == 0


@pytest.mark.parametrize("bad", ['1.0.0"; rm -rf /', "v1.0.0", "", "1.0.0\nx"])
def test_a_tag_that_is_not_a_version_is_rejected_before_any_write(repo, bad):
    before = _texts(repo)
    assert stamp_version.main([bad, "--root", str(repo)]) == 2
    assert _texts(repo) == before


def test_the_real_checkout_still_matches_every_pattern():
    """Guards the regexes against a reformat of the files they target."""
    edits, problems = stamp_version.plan(ROOT, "0.0.0")
    assert not problems, problems
    versions = {rel: old for _, rel, old, _ in edits}
    assert len(set(versions.values())) == 1, versions


# ── scripts/build.py: code signing ────────────────────────────────────────

#: 64-bit little-endian Mach-O.  The sweep identifies binaries by magic, so a
#: fixture with plausible names but no magic would test nothing.
MACHO = b"\xcf\xfa\xed\xfe" + b"\0" * 60


@pytest.fixture
def app_bundle(tmp_path):
    app = tmp_path / "quantacrypt.app"
    (app / "Contents" / "MacOS").mkdir(parents=True)
    (app / "Contents" / "MacOS" / "quantacrypt").write_bytes(MACHO)
    (app / "Contents" / "Frameworks").mkdir()
    (app / "Contents" / "Frameworks" / "libcrypto.dylib").write_bytes(MACHO)
    # No extension and no pattern the old glob list would have matched.
    (app / "Contents" / "Frameworks" / "Tcl").write_bytes(MACHO)
    (app / "Contents" / "Resources" / "tk").mkdir(parents=True)
    (app / "Contents" / "Resources" / "tk" / "init.tcl").write_text("not a binary")
    return app


def _fake_codesign(monkeypatch, fails=lambda cmd: False):
    calls: list[list[str]] = []

    def run(cmd, **kw):
        calls.append(list(cmd))
        rc = 1 if fails(cmd) else 0
        return SimpleNamespace(returncode=rc, stdout="", stderr="mock failure")

    monkeypatch.setattr(build_script, "subprocess", SimpleNamespace(run=run))
    return calls


def _is_verify(cmd):
    return "--verify" in cmd


def test_signing_success_verifies_the_finished_bundle(app_bundle, monkeypatch, capsys):
    calls = _fake_codesign(monkeypatch)
    build_script._codesign_app_bundle(str(app_bundle), name="quantacrypt")

    signed = [c[-1] for c in calls if not _is_verify(c)]
    assert str(app_bundle / "Contents" / "Frameworks" / "libcrypto.dylib") in signed
    # The extensionless framework binary the glob list could not see.
    assert str(app_bundle / "Contents" / "Frameworks" / "Tcl") in signed
    assert str(app_bundle / "Contents" / "MacOS" / "quantacrypt") in signed
    assert not any(c.endswith("init.tcl") for c in signed), "data files are not code"
    nested = signed.index(str(app_bundle / "Contents" / "Frameworks" / "libcrypto.dylib"))
    assert nested < signed.index(str(app_bundle / "Contents" / "MacOS" / "quantacrypt")), \
        "nested binaries sign before the executable that will seal them"
    assert signed[-1] == str(app_bundle), "the outer bundle is signed last"
    assert any(c[:4] == ["codesign", "--verify", "--deep", "--strict"] for c in calls)
    assert "verified" in capsys.readouterr().out


@pytest.mark.parametrize("target", ["libcrypto.dylib", "MacOS/quantacrypt", "outer"])
def test_a_signing_failure_at_any_depth_stops_the_build(
        app_bundle, monkeypatch, capsys, target):
    """It used to print "(non-fatal)" and publish the DMG anyway."""
    def fails(cmd):
        if _is_verify(cmd):
            return False
        last = cmd[-1]
        if target == "outer":
            return last == str(app_bundle)
        return last.endswith(target)

    _fake_codesign(monkeypatch, fails)
    with pytest.raises(SystemExit) as e:
        build_script._codesign_app_bundle(str(app_bundle), name="quantacrypt")
    assert e.value.code == 1
    assert "Code signing failed" in capsys.readouterr().out


def test_a_bundle_that_signs_but_does_not_verify_stops_the_build(
        app_bundle, monkeypatch, capsys):
    """Each target can sign cleanly and the bundle still be rejected."""
    _fake_codesign(monkeypatch, _is_verify)
    with pytest.raises(SystemExit) as e:
        build_script._codesign_app_bundle(str(app_bundle), name="quantacrypt")
    assert e.value.code == 1
    assert "verification failed" in capsys.readouterr().out


# ── the workflows ─────────────────────────────────────────────────────────

def _workflow(name: str) -> str:
    with open(os.path.join(WORKFLOWS, name), encoding="utf-8") as f:
        return f.read()


def _job(text: str, name: str) -> str:
    """The block for one job, from its header to the next job header."""
    heads = [m for m in re.finditer(r"(?m)^  (?P<name>[A-Za-z0-9_-]+):$", text)]
    for i, m in enumerate(heads):
        if m["name"] == name:
            end = heads[i + 1].start() if i + 1 < len(heads) else len(text)
            return text[m.start():end]
    raise AssertionError(f"no job named {name}")


def test_release_grants_write_only_to_the_two_jobs_that_need_it():
    text = _workflow("release.yml")
    assert re.search(r"(?m)^permissions:\n  contents: read$", text), \
        "workflow-scoped contents: write is inherited by every build job"
    for job in ("release", "bump-version"):
        assert "contents: write" in _job(text, job)
    for job in ("test", "build-arm64", "build-x86_64", "build-native"):
        assert "contents: write" not in _job(text, job)


def test_release_stamps_the_version_structurally():
    text = _workflow("release.yml")
    assert "sed -i" not in text, "sed exits 0 on a no-match; the stamp must fail loudly"
    assert text.count("scripts/stamp_version.py") == 4, \
        "three build jobs plus bump-version"


def test_both_tk_build_jobs_verify_the_signature_before_uploading():
    text = _workflow("release.yml")
    for job in ("build-arm64", "build-x86_64"):
        assert "codesign --verify --deep --strict dist/quantacrypt.app" in _job(text, job)


def test_bump_version_relocks_so_the_lock_cannot_lag_a_release():
    job = _job(_workflow("release.yml"), "bump-version")
    assert "uv lock" in job
    assert "uv.lock requirements-lock.txt" in job


def test_ci_runs_the_split_gate_and_the_per_file_coverage_floor():
    text = _workflow("ci.yml")
    assert "scripts/run_tests.sh" in text
    assert "scripts/check_coverage.py --min 95" in text
    assert "uv lock --check" in text
    assert re.search(r"(?m)^permissions:\n  contents: read$", text)
