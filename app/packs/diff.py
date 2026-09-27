"""What changes between two versions of a pack (Update Pack spec sections 21-22).

A *sensitive* change may weaken detection: a lower severity, a removed human
gate (``manual_review`` true -> false), any change to ``required_evidence``
(fewer keys, or added keys - missing evidence is evaluated before checks, so
it can mask a FAIL), a removed rule, or any change to a rule's
conditions/checks. Install and rollback never apply one without explicit
approval.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.models.risk import RiskRule, Severity

_SEVERITY_RANK = {Severity.LOW: 0, Severity.MEDIUM: 1, Severity.HIGH: 2, Severity.CRITICAL: 3}


@dataclass
class PackDiff:
    added: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    modified: list[str] = field(default_factory=list)  # "<id>: <what>"
    sensitive: list[str] = field(default_factory=list)  # "<id>: <why>"

    def lines(self) -> list[str]:
        out: list[str] = []
        for title, items in (
            ("Added", self.added),
            ("Modified", self.modified),
            ("Removed", self.removed),
            ("Sensitive changes (need --approve-sensitive)", self.sensitive),
        ):
            out.append(f"{title}:")
            out += [f"  - {item}" for item in items] or ["  - none"]
        return out


def _describe(old: RiskRule, new: RiskRule) -> tuple[list[str], list[str]]:
    changes: list[str] = []
    sensitive: list[str] = []
    if old.severity != new.severity:
        changes.append(f"severity {old.severity.value} -> {new.severity.value}")
        if _SEVERITY_RANK[new.severity] < _SEVERITY_RANK[old.severity]:
            sensitive.append(f"severity lowered {old.severity.value} -> {new.severity.value}")
    if old.manual_review != new.manual_review:
        changes.append(f"manual_review {old.manual_review} -> {new.manual_review}")
        if old.manual_review and not new.manual_review:
            sensitive.append("human gate removed (manual_review true -> false)")
    if set(old.required_evidence) != set(new.required_evidence):
        changes.append("required_evidence changed")
        dropped = sorted(set(old.required_evidence) - set(new.required_evidence))
        added = sorted(set(new.required_evidence) - set(old.required_evidence))
        if dropped:
            sensitive.append(f"required_evidence reduced (dropped {dropped})")
        if added:
            # Missing evidence is evaluated before checks, so a new
            # requirement can turn a FAIL into UNKNOWN (Codex re-review F18).
            sensitive.append(f"required_evidence added {added} (can mask a FAIL)")
    if old.conditions != new.conditions or old.checks != new.checks:
        changes.append("conditions/checks changed")
        # Whether a logic change weakens detection cannot be decided in
        # general (flipping `x: false` to `x: true` turns a FAIL into a PASS),
        # so every one needs explicit approval (Codex review F01).
        sensitive.append("conditions/checks changed (may weaken detection)")
    if old.title != new.title or old.mitigations != new.mitigations:
        changes.append("text changed")
    return changes, sensitive


def diff_rules(old: list[RiskRule], new: list[RiskRule]) -> PackDiff:
    before = {r.id: r for r in old}
    after = {r.id: r for r in new}
    diff = PackDiff(
        added=sorted(set(after) - set(before)),
        removed=sorted(set(before) - set(after)),
    )
    diff.sensitive += [f"{rule_id}: rule removed" for rule_id in diff.removed]
    for rule_id in sorted(set(before) & set(after)):
        changes, sensitive = _describe(before[rule_id], after[rule_id])
        if changes:
            diff.modified.append(f"{rule_id}: {', '.join(changes)}")
        diff.sensitive += [f"{rule_id}: {s}" for s in sensitive]
    return diff
