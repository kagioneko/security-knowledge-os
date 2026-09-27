"""Update Packs (docs/pack-schema.md): archive safety, verification, build,
diff, the install/rollback/remove lifecycle, and the assessment path."""

from __future__ import annotations

import hashlib
import io
import json
import zipfile
from datetime import date
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from app.config import Mode, Settings
from app.models.assessment import AssessmentInput, OverallStatus
from app.models.pack import PackTrust
from app.models.report import ReportStatus
from app.models.risk import FindingStatus, RiskRule
from app.packs import archive as archive_mod
from app.packs import store as store_mod
from app.packs.archive import PackArchiveError, read_pack_zip
from app.packs.build import BuildError, build_pack, issue_license
from app.packs.diff import diff_rules
from app.packs.loader import PackLoadError, apply_verified, load_with_packs
from app.packs.signing import TrustedKey
from app.packs.store import PackStoreError, install, load_state, remove, rollback
from app.packs.verify import PackVerifyError, Problem, VerifiedPack, verify_pack
from app.reviewer.facts import FactType
from app.reviewer.report import build_report, render_text
from app.reviewer.rule_loader import RuleCatalogue, load_rules
from app.reviewer.vocabulary import CORE_VOCABULARY, VocabularyError

TODAY = date(2026, 10, 1)
KEY_ID = "test-2026-01"
ENGINE = "0.2.0"

_RULE = """\
id: DEMO-001
title: HTTP transport without authentication
category: agent-security
severity: high
manual_review: false
conditions:
  all:
    - demo_transport: http
checks:
  - demo_auth_required: true
required_evidence: []
mitigations:
  - require authentication
"""


def _manifest(**over: Any) -> dict[str, Any]:
    m: dict[str, Any] = {
        "pack_api": 1,
        "pack_id": "demo",
        "name": "Demo Pack",
        "version": "2026.10.0",
        "release_date": "2026-10-01",
        "min_engine_version": "0.2.0",
        "classification": "public",
        "publisher": "tester",
        "license": "Apache-2.0",
        "description": "demo pack for tests",
        "facts": {
            "demo_transport": {"type": "str", "values": ["stdio", "http"]},
            "demo_auth_required": {"type": "bool"},
            "demo_roots": {"type": "str_list"},
        },
        "evidence": {"demo_launch_command": "Provide the launch command."},
        "questions": {"demo_transport": "Which transport does the server use?"},
        "report_groups": {"exposure": ["DEMO-001"]},
    }
    m.update(over)
    return m


def _src(root: Path, *, manifest: dict[str, Any] | None = None, rule: str = _RULE,
         extra: dict[str, str] | None = None) -> Path:
    src = root / "src"
    (src / "rules").mkdir(parents=True, exist_ok=True)
    (src / "manifest.json").write_text(json.dumps(manifest or _manifest()))
    (src / "rules" / "DEMO-001.yaml").write_text(rule)
    (src / "changelog.md").write_text("# 2026.10.0\n- first\n")
    for rel, text in (extra or {}).items():
        (src / rel).parent.mkdir(parents=True, exist_ok=True)
        (src / rel).write_text(text)
    return src


@pytest.fixture
def key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


@pytest.fixture
def trusted(key: Ed25519PrivateKey) -> dict[str, TrustedKey]:
    raw = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return {KEY_ID: TrustedKey(KEY_ID, "tester", raw)}


def _zip(tmp: Path, key: Ed25519PrivateKey | None = None, **kw: Any) -> Path:
    return build_pack(_src(tmp, **kw), tmp / "dist", key=key, key_id=KEY_ID if key else None)


def _files(path: Path) -> dict[str, bytes]:
    return read_pack_zip(path.read_bytes())


def _verify(files: dict[str, bytes], trusted: dict[str, TrustedKey], **kw: Any) -> VerifiedPack:
    return verify_pack(files, trusted=trusted, engine_version=ENGINE, today=TODAY, **kw)


def _raw_zip(entries: list[tuple[zipfile.ZipInfo | str, bytes]]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for info, data in entries:
            zf.writestr(info, data)
    return buf.getvalue()


# -------------------------------------------------------------- archive ----


@pytest.mark.parametrize(
    ("name", "reason"),
    [
        ("../evil.yaml", "'..'"),
        ("/etc/passwd", "absolute"),
        ("rules/../../x.yaml", "'..'"),
        ("run.py", "not allowed"),
        ("rules/sub/x.yaml", "not allowed"),
        ("rules\\x.yaml", "malformed"),
        ("knowledge/KU-1.md", "not allowed"),
    ],
)
def test_archive_rejects_unsafe_entries(name: str, reason: str) -> None:
    with pytest.raises(PackArchiveError, match=reason):
        read_pack_zip(_raw_zip([(name, b"x")]))


def test_archive_rejects_symlink_entry() -> None:
    info = zipfile.ZipInfo("rules/link.yaml")
    info.external_attr = 0o120777 << 16
    with pytest.raises(PackArchiveError, match="symlink"):
        read_pack_zip(_raw_zip([(info, b"/etc/passwd")]))


def test_archive_rejects_duplicates_and_bombs(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.warns(UserWarning):
        dup = _raw_zip([("rules/a.yaml", b"1"), ("rules/a.yaml", b"2")])
    with pytest.raises(PackArchiveError, match="duplicate"):
        read_pack_zip(dup)
    monkeypatch.setattr(archive_mod, "MAX_ENTRY_BYTES", 10)
    with pytest.raises(PackArchiveError, match="exceeds"):
        read_pack_zip(_raw_zip([("rules/a.yaml", b"x" * 1000)]))
    monkeypatch.setattr(archive_mod, "MAX_ENTRIES", 2)
    with pytest.raises(PackArchiveError, match="entries"):
        read_pack_zip(_raw_zip([(f"rules/r{i}.yaml", b"x") for i in range(3)]))


def test_archive_rejects_non_zip() -> None:
    with pytest.raises(PackArchiveError, match="not a valid ZIP"):
        read_pack_zip(b"not a zip")


# ---------------------------------------------------------------- build ----


def test_build_is_reproducible(tmp_path: Path, key: Ed25519PrivateKey) -> None:
    first = _zip(tmp_path, key).read_bytes()
    second = build_pack(tmp_path / "src", tmp_path / "dist2", key=key, key_id=KEY_ID).read_bytes()
    assert first == second


def test_build_refuses_code_and_bad_ids(tmp_path: Path) -> None:
    with pytest.raises(BuildError, match="not allowed"):
        _zip(tmp_path / "a", extra={"hook.py": "print(1)"})
    with pytest.raises(BuildError, match="manifest"):
        _zip(tmp_path / "b", manifest=_manifest(pack_id="../../x"))


def test_built_zip_carries_checksums(tmp_path: Path) -> None:
    listing = _files(_zip(tmp_path))["checksums.sha256"].decode()
    assert "rules/DEMO-001.yaml" in listing and "changelog.md" in listing


# --------------------------------------------------------------- verify ----


def test_signed_pack_verifies(tmp_path: Path, key: Ed25519PrivateKey,
                              trusted: dict[str, TrustedKey]) -> None:
    v = _verify(_files(_zip(tmp_path, key)), trusted)
    assert v.trust is PackTrust.SIGNED
    assert [r.id for r in v.catalogue.rules] == ["DEMO-001"]


def test_unsigned_needs_operator_approval(tmp_path: Path, trusted: dict[str, TrustedKey]) -> None:
    files = _files(_zip(tmp_path))
    with pytest.raises(PackVerifyError) as err:
        _verify(files, trusted)
    assert err.value.problem is Problem.UNTRUSTED
    assert _verify(files, trusted, allow_unsigned=True).trust is PackTrust.OPERATOR_APPROVED


def test_unknown_key_is_treated_as_unsigned(tmp_path: Path, key: Ed25519PrivateKey) -> None:
    with pytest.raises(PackVerifyError) as err:
        _verify(_files(_zip(tmp_path, key)), {})
    assert err.value.problem is Problem.UNTRUSTED


def test_wrong_key_and_wrong_publisher_are_invalid(
    tmp_path: Path, key: Ed25519PrivateKey
) -> None:
    other = Ed25519PrivateKey.generate()
    raw_other = other.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    files = _files(_zip(tmp_path, key))
    with pytest.raises(PackVerifyError, match="does not verify"):
        _verify(files, {KEY_ID: TrustedKey(KEY_ID, "tester", raw_other)})
    raw = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    with pytest.raises(PackVerifyError, match="publisher"):
        _verify(files, {KEY_ID: TrustedKey(KEY_ID, "someone-else", raw)})


def test_tampered_rule_fails_checksum(tmp_path: Path, key: Ed25519PrivateKey,
                                      trusted: dict[str, TrustedKey]) -> None:
    files = _files(_zip(tmp_path, key))
    files["rules/DEMO-001.yaml"] = _RULE.replace("severity: high", "severity: low").encode()
    with pytest.raises(PackVerifyError, match="sha256"):
        _verify(files, trusted)
    files = _files(_zip(tmp_path, key))
    files["rules/DEMO-999.yaml"] = b"id: DEMO-999\n"
    with pytest.raises(PackVerifyError, match="not listed"):
        _verify(files, trusted)


def test_checksums_file_must_match(tmp_path: Path, key: Ed25519PrivateKey,
                                   trusted: dict[str, TrustedKey]) -> None:
    files = _files(_zip(tmp_path, key))
    files["checksums.sha256"] = b"0" * 64 + b"  rules/DEMO-001.yaml\n"
    with pytest.raises(PackVerifyError, match="checksums.sha256"):
        _verify(files, trusted)


@pytest.mark.parametrize(
    ("over", "problem", "match"),
    [
        ({"classification": "secret"}, Problem.INVALID, "never packed"),
        ({"min_engine_version": "9.0.0"}, Problem.INCOMPATIBLE, ">= 9.0.0"),
        ({"max_engine_version": "0.1.0", "min_engine_version": "0.1.0"}, Problem.INCOMPATIBLE,
         "<= 0.1.0"),
        ({"version": "1.0.0"}, Problem.INVALID, "manifest"),
    ],
)
def test_manifest_level_rejections(trusted: dict[str, TrustedKey], over: dict[str, Any],
                                   problem: Problem, match: str) -> None:
    body = _RULE.encode()
    manifest = _manifest(**over)
    manifest["files"] = {"rules/DEMO-001.yaml": hashlib.sha256(body).hexdigest()}
    files = {"manifest.json": json.dumps(manifest).encode(), "rules/DEMO-001.yaml": body}
    with pytest.raises(PackVerifyError, match=match) as err:
        _verify(files, trusted, allow_unsigned=True)
    assert err.value.problem is problem


@pytest.mark.parametrize(
    ("kw", "match"),
    [
        ({"manifest": _manifest(facts={"roots": {"type": "str_list"}},
                                questions={}, report_groups={})}, "vocabulary"),
        ({"rule": _RULE.replace("DEMO-001", "PI-900"),
          "manifest": _manifest(report_groups={})}, "must start with 'DEMO-'"),
        ({"rule": _RULE.replace("demo_transport: http", "demo_transport: htttp")},
         "declared values"),
        ({"rule": _RULE.replace("demo_auth_required", "mcp_auth")}, "unknown fact"),
        ({"manifest": _manifest(report_groups={"x": ["DEMO-002"]})}, "unknown rule"),
    ],
)
def test_pack_content_rejections(tmp_path: Path, key: Ed25519PrivateKey,
                                 trusted: dict[str, TrustedKey], kw: dict[str, Any],
                                 match: str) -> None:
    with pytest.raises(PackVerifyError, match=match):
        _verify(_files(_zip(tmp_path, key, **kw)), trusted)


def test_pack_cannot_shadow_a_core_fact() -> None:
    with pytest.raises(VocabularyError):
        CORE_VOCABULARY.extend(
            "memory", facts={"memory_enabled": FactType.BOOL},
            fact_values={}, evidence={}, questions={},
        )
    assert "memory" not in CORE_VOCABULARY.packs


# -------------------------------------------------------------- license ----


@pytest.fixture
def cfg_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("SKOS_CONFIG_DIR", str(tmp_path / "cfg"))
    return tmp_path / "cfg"


def _license(cfg: Path, key: Ed25519PrivateKey, *, pack: str = "demo",
             expires: date = date(2027, 1, 1)) -> Path:
    return issue_license(
        cfg / "licenses", pack=pack, license_id="L-1", licensee="Example Corp",
        issued=date(2026, 9, 1), expires=expires, key=key, key_id=KEY_ID,
    )


def _commercial(tmp: Path, key: Ed25519PrivateKey) -> dict[str, bytes]:
    return _files(_zip(tmp, key, manifest=_manifest(classification="commercial")))


def test_commercial_license_lifecycle(tmp_path: Path, cfg_dir: Path, key: Ed25519PrivateKey,
                                      trusted: dict[str, TrustedKey]) -> None:
    files = _commercial(tmp_path, key)
    with pytest.raises(PackVerifyError, match="no license file") as err:
        _verify(files, trusted)
    assert err.value.problem is Problem.LICENSE

    lic = _license(cfg_dir, key)
    v = _verify(files, trusted)
    assert v.license_note == "licensed until 2027-01-01"

    lic.write_text(lic.read_text().replace("2027-01-01", "2099-01-01"))
    with pytest.raises(PackVerifyError, match="signature"):
        _verify(files, trusted)

    _license(cfg_dir, key, expires=date(2026, 9, 30))
    with pytest.raises(PackVerifyError, match="expired"):
        _verify(files, trusted)


def test_license_for_another_pack_is_rejected(tmp_path: Path, cfg_dir: Path,
                                              key: Ed25519PrivateKey,
                                              trusted: dict[str, TrustedKey]) -> None:
    _license(cfg_dir, key, pack="other")
    for suffix in (".lic", ".lic.sig"):
        (cfg_dir / "licenses" / f"other{suffix}").rename(cfg_dir / "licenses" / f"demo{suffix}")
    with pytest.raises(PackVerifyError, match="does not cover"):
        _verify(_commercial(tmp_path, key), trusted)


# ----------------------------------------------------------------- diff ----


def _rules(text: str, tmp: Path) -> list[RiskRule]:
    tmp.mkdir(parents=True)
    (tmp / "r.yaml").write_text(text)
    v = CORE_VOCABULARY.extend(
        "demo",
        facts={"demo_transport": FactType.STR, "demo_auth_required": FactType.BOOL},
        fact_values={}, evidence={"demo_launch_command": "x"}, questions={},
    )
    return load_rules(tmp, v).rules


def test_diff_flags_sensitive_changes(tmp_path: Path) -> None:
    old = _rules(_RULE.replace("manual_review: false", "manual_review: true")
                 .replace("required_evidence: []", "required_evidence: [demo_launch_command]"),
                 tmp_path / "old")
    new = _rules(_RULE.replace("severity: high", "severity: medium"), tmp_path / "new")
    text = " ".join(diff_rules(old, new).sensitive)
    assert "severity lowered high -> medium" in text
    assert "human gate removed" in text
    assert "required_evidence reduced" in text
    assert diff_rules(old, []).sensitive == ["DEMO-001: rule removed"]
    stricter = _rules(_RULE.replace("severity: high", "severity: critical"), tmp_path / "s")
    assert diff_rules(new, stricter).sensitive == []


# --------------------------------------------------------------- store -----


@pytest.fixture
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("SKOS_HOME", str(tmp_path / "home"))
    return tmp_path / "home"


def _install(zip_path: Path, catalogue: RuleCatalogue, trusted: dict[str, TrustedKey],
             **kw: Any) -> None:
    install(zip_path, catalogue, trusted=trusted, today=TODAY, **kw)


def _audit(home: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in (home / "audit.jsonl").read_text().splitlines()]


def test_install_activates_atomically_and_audits(
    tmp_path: Path, home: Path, key: Ed25519PrivateKey, trusted: dict[str, TrustedKey],
    catalogue: RuleCatalogue,
) -> None:
    _install(_zip(tmp_path, key), catalogue, trusted)
    state = load_state(home)
    assert state.packs["demo"].version == "2026.10.0"
    assert (home / "active" / "demo").is_symlink()
    assert (home / "packs" / "public" / "demo-2026.10.0.zip").is_file()
    assert (home / "installed.json").stat().st_mode & 0o777 == 0o600
    records = _audit(home)
    assert [r["install_result"] for r in records] == ["committing", "ok"]
    assert records[-1]["manifest_hash"] == state.packs["demo"].manifest_sha256

    merged, _ = load_with_packs(catalogue, trusted=trusted, today=TODAY)
    assert "DEMO-001" in {r.id for r in merged.rules}


def test_install_works_outside_a_source_checkout(
    tmp_path: Path, home: Path, key: Ed25519PrivateKey, trusted: dict[str, TrustedKey],
    catalogue: RuleCatalogue, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Regression: the smoke test used a cwd-relative safe_tests/ root, so
    `skos pack install` failed anywhere but inside a source checkout."""
    import shutil

    import app.config

    zip_path = _zip(tmp_path, key)
    bundled = tmp_path / "_bundled"  # what a wheel install ships
    shutil.copytree(Path(__file__).resolve().parents[2] / "safe_tests", bundled / "safe_tests")
    monkeypatch.setattr(app.config, "_BUNDLED", bundled)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    _install(zip_path, catalogue, trusted)
    assert load_state(home).packs["demo"].version == "2026.10.0"


def test_unsigned_install_is_rejected_and_audited(
    tmp_path: Path, home: Path, trusted: dict[str, TrustedKey], catalogue: RuleCatalogue,
) -> None:
    with pytest.raises(PackVerifyError):
        _install(_zip(tmp_path), catalogue, trusted)
    assert load_state(home).packs == {}
    assert _audit(home)[0]["install_result"] == "rejected"

    _install(_zip(tmp_path / "b"), catalogue, trusted, allow_unsigned=True)
    assert load_state(home).packs["demo"].trust is PackTrust.OPERATOR_APPROVED
    # an operator-approved pack keeps loading without the flag
    merged, _ = load_with_packs(catalogue, trusted=trusted, today=TODAY)
    assert merged.packs_applied[0].trust is PackTrust.OPERATOR_APPROVED


def _v2(tmp: Path, key: Ed25519PrivateKey, rule: str) -> Path:
    return _zip(tmp, key, manifest=_manifest(version="2026.11.0"), rule=rule)


def test_sensitive_upgrade_needs_approval_then_rollback(
    tmp_path: Path, home: Path, key: Ed25519PrivateKey, trusted: dict[str, TrustedKey],
    catalogue: RuleCatalogue,
) -> None:
    _install(_zip(tmp_path / "v1", key), catalogue, trusted)
    weaker = _v2(tmp_path / "v2", key, _RULE.replace("severity: high", "severity: low"))
    with pytest.raises(PackStoreError, match="--approve-sensitive"):
        _install(weaker, catalogue, trusted)
    assert load_state(home).packs["demo"].version == "2026.10.0"
    assert not (home / "versions" / "demo" / "2026.11.0").exists()

    _install(weaker, catalogue, trusted, approve_sensitive=True)
    state = load_state(home)
    assert state.packs["demo"].version == "2026.11.0"
    assert state.packs["demo"].history == ["2026.10.0"]

    # rolling back makes it stricter again - not sensitive
    rollback("demo", "2026.10.0", catalogue, trusted=trusted, today=TODAY)
    assert load_state(home).packs["demo"].version == "2026.10.0"
    assert _audit(home)[-1]["action"] == "rollback"


def test_released_version_cannot_change(
    tmp_path: Path, home: Path, key: Ed25519PrivateKey, trusted: dict[str, TrustedKey],
    catalogue: RuleCatalogue,
) -> None:
    _install(_zip(tmp_path / "a", key), catalogue, trusted)
    changed = _zip(tmp_path / "b", key, rule=_RULE.replace("HTTP transport", "HTTP server"))
    with pytest.raises(PackStoreError, match="never change"):
        _install(changed, catalogue, trusted)


def test_failed_smoke_test_leaves_previous_version_active(
    tmp_path: Path, home: Path, key: Ed25519PrivateKey, trusted: dict[str, TrustedKey],
    catalogue: RuleCatalogue, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install(_zip(tmp_path / "v1", key), catalogue, trusted)

    def boom(*_: object) -> None:
        raise PackStoreError("smoke test failed: simulated")

    monkeypatch.setattr(store_mod, "_smoke_test", boom)
    with pytest.raises(PackStoreError, match="simulated"):
        _install(_v2(tmp_path / "v2", key, _RULE), catalogue, trusted)
    assert load_state(home).packs["demo"].version == "2026.10.0"
    versions = sorted(p.name for p in (home / "versions" / "demo").iterdir())
    assert versions == ["2026.10.0"]  # no staging leftovers


def test_confidential_pack_needs_approval(
    tmp_path: Path, home: Path, key: Ed25519PrivateKey, trusted: dict[str, TrustedKey],
    catalogue: RuleCatalogue,
) -> None:
    conf = _zip(tmp_path, key, manifest=_manifest(classification="confidential"))
    with pytest.raises(PackStoreError, match="confidential"):
        _install(conf, catalogue, trusted)
    _install(conf, catalogue, trusted, approve_sensitive=True)


def test_tampered_installed_pack_stops_assessment(
    tmp_path: Path, home: Path, key: Ed25519PrivateKey, trusted: dict[str, TrustedKey],
    catalogue: RuleCatalogue,
) -> None:
    _install(_zip(tmp_path, key), catalogue, trusted)
    rule = home / "versions" / "demo" / "2026.10.0" / "rules" / "DEMO-001.yaml"
    rule.write_text(_RULE.replace("severity: high", "severity: low"))
    with pytest.raises(PackLoadError, match="sha256"):
        load_with_packs(catalogue, trusted=trusted, today=TODAY)


def test_extra_file_in_installed_pack_stops_assessment(
    tmp_path: Path, home: Path, key: Ed25519PrivateKey, trusted: dict[str, TrustedKey],
    catalogue: RuleCatalogue,
) -> None:
    _install(_zip(tmp_path, key), catalogue, trusted)
    (home / "versions" / "demo" / "2026.10.0" / "run.py").write_text("print(1)\n")
    with pytest.raises(PackLoadError, match="unexpected file"):
        load_with_packs(catalogue, trusted=trusted, today=TODAY)


def test_rollback_rejects_path_like_versions(
    tmp_path: Path, home: Path, key: Ed25519PrivateKey, trusted: dict[str, TrustedKey],
    catalogue: RuleCatalogue,
) -> None:
    _install(_zip(tmp_path, key), catalogue, trusted)
    with pytest.raises(PackStoreError, match="YYYY.MM.PATCH"):
        rollback("demo", "../../etc", catalogue, trusted=trusted, today=TODAY)


def test_remove_keeps_history(
    tmp_path: Path, home: Path, key: Ed25519PrivateKey, trusted: dict[str, TrustedKey],
    catalogue: RuleCatalogue,
) -> None:
    _install(_zip(tmp_path, key), catalogue, trusted)
    remove("demo")
    assert load_state(home).packs == {}
    assert not (home / "active" / "demo").exists()
    assert (home / "versions" / "demo" / "2026.10.0").is_dir()
    merged, _ = load_with_packs(catalogue, trusted=trusted, today=TODAY)
    assert merged.packs_applied == []


def test_expired_commercial_pack_is_skipped_not_fatal(
    tmp_path: Path, home: Path, cfg_dir: Path, key: Ed25519PrivateKey,
    trusted: dict[str, TrustedKey], catalogue: RuleCatalogue,
) -> None:
    _license(cfg_dir, key)
    _install(_zip(tmp_path, key, manifest=_manifest(classification="commercial")), catalogue,
             trusted)
    merged, active = load_with_packs(catalogue, trusted=trusted, today=date(2027, 6, 1))
    assert merged.packs_applied == []
    assert active[0].problem is not None and active[0].problem.problem is Problem.LICENSE


# ----------------------------------------------------- assessment path ----


@pytest.fixture
def settings() -> Settings:
    return Settings(mode=Mode.PRIVATE)


@pytest.fixture
def demo_catalogue(tmp_path: Path, key: Ed25519PrivateKey, trusted: dict[str, TrustedKey],
                   catalogue: RuleCatalogue) -> RuleCatalogue:
    return apply_verified(catalogue, [_verify(_files(_zip(tmp_path, key)), trusted)])


def _input(**demo: object) -> AssessmentInput:
    return AssessmentInput.model_validate({"name": "t", "extensions": {"demo": demo}})


def test_pack_rule_fires_and_is_recorded(demo_catalogue: RuleCatalogue,
                                         settings: Settings) -> None:
    report = build_report(
        _input(transport="http", auth_required=False, launch_command="npx demo@1.0.0"),
        demo_catalogue, settings=settings,
    )
    assert report.status is ReportStatus.COMPLETED and report.result is not None
    r = report.result
    demo = [f for f in r.findings if f.risk_id == "DEMO-001"]
    assert demo and demo[0].status is FindingStatus.FAIL
    assert r.overall_status is OverallStatus.FAIL
    assert [p.pack_id for p in r.packs_applied] == ["demo"]
    [group] = r.group_summaries
    assert (group.group, group.worst_status, group.finding_count) == (
        "exposure", FindingStatus.FAIL, 1,
    )
    text = render_text(report)
    assert "packs: demo 2026.10.0 [public, signed]" in text and "demo/exposure" in text


def test_undetermined_trigger_becomes_a_question(demo_catalogue: RuleCatalogue,
                                                 settings: Settings) -> None:
    report = build_report(_input(auth_required=False), demo_catalogue, settings=settings)
    assert report.result is not None
    assert any(q.field == "demo_transport" and "Which transport" in q.text
               for q in report.result.questions)


@pytest.mark.parametrize(
    ("demo", "reason"),
    [
        ({"transport": "carrier-pigeon"}, "expected one of"),
        ({"auth_required": "yes"}, "expected true/false"),
        ({"not_declared": True}, "not declared"),
        ({"roots": "~"}, "expected a list"),
    ],
)
def test_bad_extension_values_are_blocked(demo_catalogue: RuleCatalogue, settings: Settings,
                                          demo: dict[str, object], reason: str) -> None:
    report = build_report(_input(**demo), demo_catalogue, settings=settings)
    assert report.status is ReportStatus.POLICY_BLOCKED and report.policy_decision is not None
    assert reason in " ".join(report.policy_decision.reasons)


def test_extensions_for_a_missing_pack_are_blocked(catalogue: RuleCatalogue,
                                                   settings: Settings) -> None:
    report = build_report(_input(transport="http"), catalogue, settings=settings)
    assert report.status is ReportStatus.POLICY_BLOCKED and report.policy_decision is not None
    assert "no enabled pack named 'demo'" in " ".join(report.policy_decision.reasons)


def test_no_packs_ignores_extensions_visibly(rules_root: Path, settings: Settings) -> None:
    core = load_rules(rules_root)
    core.ignore_extensions = True
    report = build_report(_input(transport="http"), core, settings=settings)
    assert report.status is ReportStatus.COMPLETED and report.result is not None
    assert report.result.extensions_ignored is True
    assert "extensions: IGNORED" in render_text(report)


def test_extension_values_reject_credential_shapes() -> None:
    with pytest.raises(ValueError):
        _input(launch_command="API_KEY=" + "sk-ant-" + "a" * 90)


def test_builtin_trust_store_is_well_formed() -> None:
    from app.packs.trusted_keys import TRUSTED_KEYS

    assert set(TRUSTED_KEYS) == {"kagioneko-2026-01"}
    key = TRUSTED_KEYS["kagioneko-2026-01"]
    assert key.publisher == "kagioneko" and len(key.public_key) == 32


def test_undetermined_check_becomes_a_question(demo_catalogue: RuleCatalogue,
                                               settings: Settings) -> None:
    """The rule applies (transport=http) but its check fact is unknown: the
    finding is UNKNOWN *and* the missing fact is asked for."""
    report = build_report(_input(transport="http"), demo_catalogue, settings=settings)
    assert report.result is not None
    [finding] = [f for f in report.result.findings if f.risk_id == "DEMO-001"]
    assert finding.status is FindingStatus.UNKNOWN
    assert any(q.field == "demo_auth_required" for q in report.result.questions)
    assert any(m.field == "demo_auth_required" for m in report.result.missing_information)


def test_only_pack_scope_is_explicit(demo_catalogue: RuleCatalogue, settings: Settings) -> None:
    from app.packs.loader import only_pack

    scoped = only_pack(demo_catalogue, "demo")
    assert [r.id for r in scoped.rules] == ["DEMO-001"]
    report = build_report(_input(transport="http", auth_required=False), scoped,
                          settings=settings)
    assert report.result is not None
    assert {f.risk_id for f in report.result.findings} == {"DEMO-001"}
    assert report.result.rule_scope == "pack:demo"
    assert "core rules were NOT evaluated" in render_text(report)
    with pytest.raises(PackLoadError, match="no active pack"):
        only_pack(demo_catalogue, "other")


# ------------------------------------------- Codex review regressions ----


def test_f01_check_logic_change_is_sensitive(tmp_path: Path) -> None:
    old = _rules(_RULE, tmp_path / "old")
    flipped = _rules(_RULE.replace("demo_auth_required: true", "demo_auth_required: false"),
                     tmp_path / "new")
    assert any("conditions/checks changed" in s for s in diff_rules(old, flipped).sensitive)


@pytest.mark.parametrize(
    ("signed", "match"),
    [(True, "do not match the recorded installation"), (False, "unsigned")],
)
def test_f02_replayed_older_version_is_detected(
    tmp_path: Path, home: Path, key: Ed25519PrivateKey, trusted: dict[str, TrustedKey],
    catalogue: RuleCatalogue, signed: bool, match: str,
) -> None:
    """An older, once-valid version swapped into the active version's
    directory: a signed one fails the registry match, an unsigned one is no
    longer the approved manifest."""
    import shutil

    k = key if signed else None
    _install(_zip(tmp_path / "v1", k), catalogue, trusted, allow_unsigned=not signed)
    _install(_zip(tmp_path / "v2", k, manifest=_manifest(version="2026.11.0")), catalogue,
             trusted, allow_unsigned=not signed)
    new_dir = home / "versions" / "demo" / "2026.11.0"
    shutil.rmtree(new_dir)
    shutil.copytree(home / "versions" / "demo" / "2026.10.0", new_dir)
    with pytest.raises(PackLoadError, match=match):
        load_with_packs(catalogue, trusted=trusted, today=TODAY)


def test_f05_failed_activation_restores_state(
    tmp_path: Path, home: Path, key: Ed25519PrivateKey, trusted: dict[str, TrustedKey],
    catalogue: RuleCatalogue, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install(_zip(tmp_path / "v1", key), catalogue, trusted)

    def fail(*_: object) -> None:
        raise OSError("simulated symlink failure")

    original = store_mod._activate
    monkeypatch.setattr(store_mod, "_activate", fail)
    with pytest.raises(OSError, match="simulated"):
        _install(_v2(tmp_path / "v2", key, _RULE), catalogue, trusted)
    assert load_state(home).packs["demo"].version == "2026.10.0"
    monkeypatch.setattr(store_mod, "_activate", original)  # keep SKOS_HOME patched
    merged, _ = load_with_packs(catalogue, trusted=trusted, today=TODAY)
    assert merged.packs_applied[0].version == "2026.10.0"


def test_f06_lost_registry_with_active_link_is_an_error(
    tmp_path: Path, home: Path, key: Ed25519PrivateKey, trusted: dict[str, TrustedKey],
    catalogue: RuleCatalogue,
) -> None:
    _install(_zip(tmp_path, key), catalogue, trusted)
    (home / "installed.json").write_text("{}")
    with pytest.raises(PackLoadError, match="missing from installed.json"):
        load_with_packs(catalogue, trusted=trusted, today=TODAY)
    (home / "installed.json").unlink()
    with pytest.raises(PackLoadError, match="missing from installed.json"):
        load_with_packs(catalogue, trusted=trusted, today=TODAY)
    remove("demo")  # the documented way out
    merged, _ = load_with_packs(catalogue, trusted=trusted, today=TODAY)
    assert merged.packs_applied == []


def test_f07_rollback_to_confidential_needs_approval(
    tmp_path: Path, home: Path, key: Ed25519PrivateKey, trusted: dict[str, TrustedKey],
    catalogue: RuleCatalogue,
) -> None:
    conf = _zip(tmp_path / "a", key, manifest=_manifest(classification="confidential"))
    _install(conf, catalogue, trusted, approve_sensitive=True)
    _install(_zip(tmp_path / "b", key, manifest=_manifest(version="2026.11.0")), catalogue,
             trusted)
    with pytest.raises(PackStoreError, match="confidential"):
        rollback("demo", "2026.10.0", catalogue, trusted=trusted, today=TODAY)
    rollback("demo", "2026.10.0", catalogue, trusted=trusted, today=TODAY,
             approve_sensitive=True)


def test_f13_skipped_pack_is_disclosed(
    tmp_path: Path, home: Path, cfg_dir: Path, key: Ed25519PrivateKey,
    trusted: dict[str, TrustedKey], catalogue: RuleCatalogue, settings: Settings,
) -> None:
    _license(cfg_dir, key)
    _install(_zip(tmp_path, key, manifest=_manifest(classification="commercial")), catalogue,
             trusted)
    merged, _ = load_with_packs(catalogue, trusted=trusted, today=date(2027, 6, 1))
    report = build_report(AssessmentInput(name="t"), merged, settings=settings)
    assert report.result is not None
    [skipped] = report.result.packs_skipped
    assert skipped.pack_id == "demo" and "expired" in skipped.reason
    assert "pack NOT applied: demo" in render_text(report)


def test_f14_control_characters_in_display_text_are_rejected(
    trusted: dict[str, TrustedKey],
) -> None:
    body = _RULE.encode()
    manifest = _manifest(name="Demo\x1b[2J\nsignature     : VERIFIED")
    manifest["files"] = {"rules/DEMO-001.yaml": hashlib.sha256(body).hexdigest()}
    files = {"manifest.json": json.dumps(manifest).encode(), "rules/DEMO-001.yaml": body}
    with pytest.raises(PackVerifyError, match="control"):
        _verify(files, trusted, allow_unsigned=True)


def test_f15_corrupt_deflate_and_huge_ints_are_typed_errors(
    tmp_path: Path, trusted: dict[str, TrustedKey],
) -> None:
    data = bytearray(_raw_zip_deflated([("rules/a.yaml", b"x" * 5000)]))
    start = data.index(b"rules/a.yaml") + len("rules/a.yaml")
    for i in range(start, start + 20):
        data[i] ^= 0xFF
    with pytest.raises(PackArchiveError):
        read_pack_zip(bytes(data))
    files = {"manifest.json": b'{"pack_api": ' + b"9" * 5000 + b"}"}
    with pytest.raises(PackVerifyError, match="not valid"):
        _verify(files, trusted)


def _raw_zip_deflated(entries: list[tuple[str, bytes]]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, payload in entries:
            zf.writestr(name, payload)
    return buf.getvalue()
