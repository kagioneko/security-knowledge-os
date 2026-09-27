"""Service packs (docs/pack-schema.md): trust, integrity, namespacing, license,
extensions, and the rule that pack code never runs during an assessment."""

from __future__ import annotations

import textwrap
from datetime import date
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from app.config import Mode, Settings
from app.models.assessment import AssessmentInput, OverallStatus
from app.models.pack import PackTrust
from app.models.report import ReportStatus
from app.models.risk import FindingStatus
from app.packs.build import issue_license, sign_manifest, update_manifest_files
from app.packs.commands import run_command
from app.packs.config import PackConfig
from app.packs.discovery import PackCandidate
from app.packs.loader import (
    PackLoadError,
    PackState,
    apply_packs,
    inspect_all,
    inspect_pack,
)
from app.packs.signing import TrustedKey
from app.reviewer.report import build_report, render_text
from app.reviewer.rule_loader import RuleCatalogue, load_rules
from app.reviewer.vocabulary import CORE_VOCABULARY, VocabularyError

TODAY = date(2026, 10, 1)
KEY_ID = "test-2026-01"

_MANIFEST = """\
pack_api: 1
name: demo
version: 0.1.0
tier: {tier}
publisher: tester
license: Apache-2.0
description: demo pack for tests
facts:
  demo_transport: {{type: str, values: [stdio, http]}}
  demo_auth_required: {{type: bool}}
  demo_roots: {{type: str_list}}
evidence:
  demo_launch_command: Provide the launch command.
questions:
  demo_transport: Which transport does the server use (stdio or http)?
report_groups:
  exposure: [DEMO-001]
commands:
  hello: skos_pack_demo.cli:main
"""

_RULE = """\
id: DEMO-001
title: HTTP transport without authentication
category: agent-security
severity: high
conditions:
  all:
    - demo_transport: http
checks:
  - demo_auth_required: true
mitigations:
  - require authentication
"""

_CLI = """\
from pathlib import Path


def main(argv):
    Path(argv[0]).write_text("ran:" + __file__)
    return 7
"""


def _key() -> tuple[Ed25519PrivateKey, dict[str, TrustedKey]]:
    key = Ed25519PrivateKey.generate()
    raw = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return key, {KEY_ID: TrustedKey(KEY_ID, "tester", raw)}


def _make_pack(
    root: Path, *, tier: str = "free", rule: str = _RULE, manifest: str | None = None,
    init: str = "",
) -> Path:
    pack = root / "skos_pack_demo"
    (pack / "rules").mkdir(parents=True)
    (pack / "__init__.py").write_text(init)
    (pack / "cli.py").write_text(_CLI)
    (pack / "rules" / "DEMO-001.yaml").write_text(rule)
    (pack / "pack.yaml").write_text((manifest or _MANIFEST).format(tier=tier))
    update_manifest_files(pack)
    return pack


def _candidate(pack: Path) -> PackCandidate:
    return PackCandidate(pack.name, pack, "SKOS_PACK_DIRS")


def _inspect(pack: Path, trusted: dict[str, TrustedKey] | None = None,
             config: PackConfig | None = None):  # type: ignore[no-untyped-def]
    return inspect_pack(
        _candidate(pack), config or PackConfig(), trusted=trusted or {}, today=TODAY
    )


def _enabled(status_sha: str | None) -> PackConfig:
    assert status_sha
    return PackConfig(enabled={"demo": status_sha})


@pytest.fixture
def settings() -> Settings:
    return Settings(mode=Mode.PRIVATE)


def _input(**demo: object) -> AssessmentInput:
    return AssessmentInput.model_validate({"name": "t", "extensions": {"demo": demo}})


# ---------------------------------------------------------------- trust ----


def test_unsigned_pack_is_disabled_until_enabled(tmp_path: Path) -> None:
    pack = _make_pack(tmp_path)
    status, loaded = _inspect(pack)
    assert status.state is PackState.DISABLED and loaded is None
    assert "not trusted" in status.reason

    status2, loaded2 = _inspect(pack, config=_enabled(status.manifest_sha256))
    assert status2.state is PackState.ACTIVE, status2.reason
    assert loaded2 is not None and loaded2.applied.trust is PackTrust.USER_ENABLED


def test_signed_pack_loads_automatically(tmp_path: Path) -> None:
    key, trusted = _key()
    pack = _make_pack(tmp_path)
    sign_manifest(pack, key, KEY_ID)
    status, loaded = _inspect(pack, trusted)
    assert status.state is PackState.ACTIVE, status.reason
    assert loaded is not None and loaded.applied.trust is PackTrust.SIGNED


def test_manifest_changed_after_enable_is_disabled(tmp_path: Path) -> None:
    pack = _make_pack(tmp_path)
    old_sha = _inspect(pack)[0].manifest_sha256
    (pack / "pack.yaml").write_text(
        (pack / "pack.yaml").read_text().replace("version: 0.1.0", "version: 0.1.1")
    )
    status, _ = _inspect(pack, config=_enabled(old_sha))
    assert status.state is PackState.DISABLED
    assert "manifest changed" in status.reason


def test_operator_disable_wins_over_signature(tmp_path: Path) -> None:
    key, trusted = _key()
    pack = _make_pack(tmp_path)
    sign_manifest(pack, key, KEY_ID)
    status, _ = _inspect(pack, trusted, PackConfig(disabled=["demo"]))
    assert status.state is PackState.DISABLED


def test_tampered_rule_after_signing_is_an_error(tmp_path: Path) -> None:
    key, trusted = _key()
    pack = _make_pack(tmp_path)
    sign_manifest(pack, key, KEY_ID)
    (pack / "rules" / "DEMO-001.yaml").write_text(_RULE.replace("severity: high", "severity: low"))
    status, loaded = _inspect(pack, trusted)
    assert status.state is PackState.ERROR and loaded is None
    assert "sha256" in status.reason


def test_unlisted_extra_file_is_an_error(tmp_path: Path) -> None:
    key, trusted = _key()
    pack = _make_pack(tmp_path)
    sign_manifest(pack, key, KEY_ID)
    (pack / "evil.py").write_text("raise SystemExit('should never run')\n")
    status, _ = _inspect(pack, trusted)
    assert status.state is PackState.ERROR
    assert "not listed" in status.reason


def test_pycache_is_ignored(tmp_path: Path) -> None:
    key, trusted = _key()
    pack = _make_pack(tmp_path)
    sign_manifest(pack, key, KEY_ID)
    (pack / "__pycache__").mkdir()
    (pack / "__pycache__" / "cli.cpython-312.pyc").write_bytes(b"\0")
    assert _inspect(pack, trusted)[0].state is PackState.ACTIVE


def test_signature_by_wrong_key_is_an_error(tmp_path: Path) -> None:
    _, trusted = _key()
    other, _ = _key()
    pack = _make_pack(tmp_path)
    sign_manifest(pack, other, KEY_ID)  # right key id, wrong key
    status, _ = _inspect(pack, trusted)
    assert status.state is PackState.ERROR
    assert "does not verify" in status.reason


def test_signature_by_unknown_key_falls_back_to_operator(tmp_path: Path) -> None:
    key, _ = _key()
    pack = _make_pack(tmp_path)
    sign_manifest(pack, key, "someone-else-01")
    status, _ = _inspect(pack, {})
    assert status.state is PackState.DISABLED and "not trusted" in status.reason


def test_publisher_mismatch_is_an_error(tmp_path: Path) -> None:
    key, _ = _key()
    raw = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    trusted = {KEY_ID: TrustedKey(KEY_ID, "someone-else", raw)}
    pack = _make_pack(tmp_path)
    sign_manifest(pack, key, KEY_ID)
    status, _ = _inspect(pack, trusted)
    assert status.state is PackState.ERROR
    assert "publisher" in status.reason


def test_symlink_in_pack_is_refused(tmp_path: Path) -> None:
    pack = _make_pack(tmp_path)
    (pack / "link.yaml").symlink_to(pack / "pack.yaml")
    status, _ = _inspect(pack)
    assert status.state is PackState.DISABLED and "unreadable" in status.reason


def test_error_pack_blocks_apply(tmp_path: Path, catalogue: RuleCatalogue) -> None:
    key, trusted = _key()
    pack = _make_pack(tmp_path)
    sign_manifest(pack, key, KEY_ID)
    (pack / "cli.py").write_text("# changed\n")
    inspected = [_inspect(pack, trusted)]
    with pytest.raises(PackLoadError):
        apply_packs(catalogue, inspected)


# ---------------------------------------------------------- namespacing ----


def _enabled_status(tmp_path: Path, **kw: str):  # type: ignore[no-untyped-def]
    pack = _make_pack(tmp_path, **kw)
    sha = _inspect(pack)[0].manifest_sha256
    return _inspect(pack, config=_enabled(sha))[0]


def test_fact_without_pack_prefix_is_rejected(tmp_path: Path) -> None:
    manifest = _MANIFEST.replace("demo_roots:", "roots:")
    status = _enabled_status(tmp_path, manifest=manifest)
    assert status.state is PackState.ERROR and "vocabulary" in status.reason


def test_rule_id_without_pack_prefix_is_rejected(tmp_path: Path) -> None:
    manifest = _MANIFEST.replace("[DEMO-001]", "[PI-900]")
    rule = _RULE.replace("DEMO-001", "PI-900")
    status = _enabled_status(tmp_path, manifest=manifest, rule=rule)
    assert status.state is PackState.ERROR and "must start with 'DEMO-'" in status.reason


def test_enum_typo_in_rule_is_rejected(tmp_path: Path) -> None:
    status = _enabled_status(tmp_path, rule=_RULE.replace("demo_transport: http",
                                                          "demo_transport: htttp"))
    assert status.state is PackState.ERROR and "declared values" in status.reason


def test_rule_cannot_reference_other_packs_facts(tmp_path: Path) -> None:
    status = _enabled_status(tmp_path, rule=_RULE.replace("demo_auth_required", "mcp_auth"))
    assert status.state is PackState.ERROR and "unknown fact" in status.reason


def test_pack_cannot_shadow_a_core_fact() -> None:
    with pytest.raises(VocabularyError):
        CORE_VOCABULARY.extend(
            "memory", facts={"memory_enabled": CORE_VOCABULARY.facts["memory_enabled"]},
            fact_values={}, evidence={}, questions={},
        )
    assert "memory" not in CORE_VOCABULARY.packs  # the core vocabulary is untouched


def test_duplicate_rule_id_with_core_is_rejected(tmp_path: Path, catalogue: RuleCatalogue) -> None:
    status, loaded = _inspect(_make_pack(tmp_path))
    status, loaded = _inspect(tmp_path / "skos_pack_demo", config=_enabled(status.manifest_sha256))
    assert loaded is not None
    loaded.catalogue.rules.append(catalogue.rules[0])
    with pytest.raises(PackLoadError, match="duplicate rule id"):
        apply_packs(catalogue, [(status, loaded)])


# -------------------------------------------------------------- license ----


def _commercial(tmp_path: Path) -> tuple[Path, Ed25519PrivateKey, dict[str, TrustedKey]]:
    key, trusted = _key()
    pack = _make_pack(tmp_path / "pk", tier="commercial")
    sign_manifest(pack, key, KEY_ID)
    return pack, key, trusted


def _license(tmp_path: Path, key: Ed25519PrivateKey, *, pack: str = "demo",
             expires: date = date(2027, 1, 1)) -> None:
    issue_license(
        tmp_path / "cfg" / "licenses", pack=pack, license_id="L-1", licensee="Example Corp",
        issued=date(2026, 9, 1), expires=expires, key=key, key_id=KEY_ID,
    )


@pytest.fixture
def cfg_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("SKOS_CONFIG_DIR", str(tmp_path / "cfg"))
    return tmp_path / "cfg"


def test_commercial_pack_without_license_is_disabled(tmp_path: Path, cfg_dir: Path) -> None:
    pack, _, trusted = _commercial(tmp_path)
    status, _ = _inspect(pack, trusted)
    assert status.state is PackState.DISABLED and "no license file" in status.reason


def test_commercial_pack_with_valid_license_is_active(tmp_path: Path, cfg_dir: Path) -> None:
    pack, key, trusted = _commercial(tmp_path)
    _license(tmp_path, key)
    status, _ = _inspect(pack, trusted)
    assert status.state is PackState.ACTIVE, status.reason
    assert "licensed until 2027-01-01" in status.reason
    assert "Example Corp" not in status.reason  # the licensee never reaches a report


def test_expired_license_is_disabled(tmp_path: Path, cfg_dir: Path) -> None:
    pack, key, trusted = _commercial(tmp_path)
    _license(tmp_path, key, expires=date(2026, 9, 30))
    status, _ = _inspect(pack, trusted)
    assert status.state is PackState.DISABLED and "expired" in status.reason


def test_license_for_another_pack_is_disabled(tmp_path: Path, cfg_dir: Path) -> None:
    pack, key, trusted = _commercial(tmp_path)
    _license(tmp_path, key, pack="other")
    (cfg_dir / "licenses" / "other.lic").rename(cfg_dir / "licenses" / "demo.lic")
    (cfg_dir / "licenses" / "other.lic.sig").rename(cfg_dir / "licenses" / "demo.lic.sig")
    status, _ = _inspect(pack, trusted)
    assert status.state is PackState.DISABLED and "does not cover" in status.reason


def test_edited_license_fails_its_signature(tmp_path: Path, cfg_dir: Path) -> None:
    pack, key, trusted = _commercial(tmp_path)
    _license(tmp_path, key)
    lic = cfg_dir / "licenses" / "demo.lic"
    lic.write_text(lic.read_text().replace("2027-01-01", "2099-01-01"))
    status, _ = _inspect(pack, trusted)
    assert status.state is PackState.DISABLED and "signature" in status.reason


# ----------------------------------------------------- assessment path ----


@pytest.fixture
def demo_catalogue(tmp_path: Path, catalogue: RuleCatalogue) -> RuleCatalogue:
    marker = tmp_path / "imported.marker"
    pack = _make_pack(tmp_path / "p", init=f"open({str(marker)!r}, 'w').close()\n")
    sha = _inspect(pack)[0].manifest_sha256
    return apply_packs(catalogue, [_inspect(pack, config=_enabled(sha))])


def test_pack_rule_fires_and_is_recorded(
    demo_catalogue: RuleCatalogue, settings: Settings, tmp_path: Path
) -> None:
    report = build_report(
        _input(transport="http", auth_required=False, launch_command="npx demo@1.0.0"),
        demo_catalogue, settings=settings,
    )
    assert report.status is ReportStatus.COMPLETED
    r = report.result
    assert r is not None
    demo = [f for f in r.findings if f.risk_id == "DEMO-001"]
    assert demo and demo[0].status is FindingStatus.FAIL
    assert r.overall_status is OverallStatus.FAIL
    assert [p.name for p in r.packs_applied] == ["demo"]
    [group] = r.group_summaries
    assert (group.group, group.worst_status, group.finding_count) == (
        "exposure", FindingStatus.FAIL, 1,
    )
    text = render_text(report)
    assert "packs: demo 0.1.0 [free, user-enabled]" in text
    assert "demo/exposure" in text
    # Pack code never runs on the assessment path.
    assert not (tmp_path / "imported.marker").exists()


def test_undetermined_pack_fact_becomes_a_question(
    demo_catalogue: RuleCatalogue, settings: Settings
) -> None:
    # Questions come from undetermined trigger conditions (as for core rules).
    report = build_report(_input(auth_required=False), demo_catalogue, settings=settings)
    assert report.result is not None
    assert any(
        q.field == "demo_transport" and "Which transport" in q.text
        for q in report.result.questions
    )


@pytest.mark.parametrize(
    ("demo", "reason"),
    [
        ({"transport": "carrier-pigeon"}, "expected one of"),
        ({"auth_required": "yes"}, "expected true/false"),
        ({"not_declared": True}, "not declared"),
        ({"roots": "~"}, "expected a list"),
    ],
)
def test_bad_extension_values_are_blocked(
    demo_catalogue: RuleCatalogue, settings: Settings, demo: dict[str, object], reason: str
) -> None:
    report = build_report(_input(**demo), demo_catalogue, settings=settings)
    assert report.status is ReportStatus.POLICY_BLOCKED
    assert report.policy_decision is not None
    assert reason in " ".join(report.policy_decision.reasons)


def test_extensions_for_a_missing_pack_are_blocked(
    catalogue: RuleCatalogue, settings: Settings
) -> None:
    report = build_report(_input(transport="http"), catalogue, settings=settings)
    assert report.status is ReportStatus.POLICY_BLOCKED
    assert "no enabled pack named 'demo'" in " ".join(report.policy_decision.reasons)  # type: ignore[union-attr]


def test_no_packs_ignores_extensions_visibly(
    rules_root: Path, settings: Settings
) -> None:
    core = load_rules(rules_root)
    core.ignore_extensions = True
    report = build_report(_input(transport="http"), core, settings=settings)
    assert report.status is ReportStatus.COMPLETED and report.result is not None
    assert report.result.extensions_ignored is True
    assert "extensions: IGNORED" in render_text(report)


def test_extension_values_reject_credential_shapes() -> None:
    with pytest.raises(ValueError):
        _input(launch_command="API_KEY=" + "sk-ant-" + "a" * 90)


# -------------------------------------------------------------- commands ----


def test_command_runs_from_the_verified_snapshot(tmp_path: Path) -> None:
    pack = _make_pack(tmp_path / "p")
    sha = _inspect(pack)[0].manifest_sha256
    status, _ = _inspect(pack, config=_enabled(sha))
    out = tmp_path / "out.txt"
    try:
        assert run_command(status, "hello", [str(out)]) == 7
        ran_from = out.read_text().removeprefix("ran:")
        assert status.snapshot is not None
        assert Path(ran_from).resolve().is_relative_to(status.snapshot.resolve())
    finally:
        import sys

        for name in [m for m in sys.modules if m.startswith("skos_pack_demo")]:
            del sys.modules[name]


def test_inspect_all_with_env_dirs(
    tmp_path: Path, cfg_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pack = _make_pack(tmp_path / "p")
    monkeypatch.setenv("SKOS_PACK_DIRS", str(pack))
    monkeypatch.setattr("app.packs.discovery._from_entry_points", lambda: [])
    [(status, _)] = inspect_all(trusted={}, today=TODAY)
    assert status.label == "skos_pack_demo" and status.state is PackState.DISABLED


def test_manifest_rejects_path_traversal(tmp_path: Path) -> None:
    pack = _make_pack(tmp_path)
    text = (pack / "pack.yaml").read_text()
    (pack / "pack.yaml").write_text(text + "  a/../../etc/passwd: " + "0" * 64 + "\n")
    status, _ = _inspect(pack)
    assert status.state is PackState.DISABLED and "invalid pack.yaml" in status.reason


def test_manifest_command_outside_own_package_is_rejected(tmp_path: Path) -> None:
    manifest = _MANIFEST.replace("skos_pack_demo.cli:main", "os.path:join")
    pack = _make_pack(tmp_path, manifest=manifest)
    status, _ = _inspect(pack)
    assert status.state is PackState.DISABLED and "invalid pack.yaml" in status.reason


def test_readme_example_manifest_parses() -> None:
    """The manifest format above stays loadable via YAML (guards the test's own
    fixture against drift from app/packs/manifest.py)."""
    import yaml

    from app.packs.manifest import PackManifest

    data = yaml.safe_load(textwrap.dedent(_MANIFEST.format(tier="free")) + "files: {}\n")
    assert PackManifest.model_validate(data).package == "skos_pack_demo"


def test_builtin_trust_store_is_well_formed() -> None:
    from app.packs.trusted_keys import TRUSTED_KEYS

    assert set(TRUSTED_KEYS) == {"kagioneko-2026-01"}
    key = TRUSTED_KEYS["kagioneko-2026-01"]
    assert key.publisher == "kagioneko" and len(key.public_key) == 32
