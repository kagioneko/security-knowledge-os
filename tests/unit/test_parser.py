"""Front-matter YAML parsing: merge-key ban and size bound (round 3, 2026-09-12)."""

from __future__ import annotations

import pytest

from app.ingestion.parser import FrontMatterError, split_front_matter


def test_plain_alias_still_works() -> None:
    """A bare alias (no merge key) just shares the referenced object - it is
    not the mapping-multiplication vector and stays legal."""
    text = "---\na: &a value\nb: *a\n---\nbody"
    data, body = split_front_matter(text)
    assert data == {"a": "value", "b": "value"}
    assert body == "body"


def test_merge_key_is_rejected() -> None:
    """Regression for Codex cross-review finding #2 (round 3, 2026-09-12),
    reproduced exactly as reported: ``yaml.safe_load`` resolves a mapping
    merge (``<<: *anchor``) by *copying* the merged mapping's values into the
    new one - chaining several such merges multiplies the materialized size
    at every level (a 285-byte document was observed expanding past 100,000
    mapping pairs this way). Front matter is a flat mapping of scalar fields
    and never legitimately needs merge keys, so they are refused outright."""
    text = "---\na: &a {x: 1}\nb:\n  <<: *a\n  y: 2\n---\nbody"
    with pytest.raises(FrontMatterError, match="merge key"):
        split_front_matter(text)


def test_merge_key_bomb_is_rejected_before_any_expansion() -> None:
    """The actual reported repro shape: chained merges that would otherwise
    expand a small document into a huge number of mapping pairs. Must fail
    fast (no timeout / MemoryError), not just "eventually" reject."""
    lines = ["a: &l0 {id: KU-0001}"]
    prev = "l0"
    for i in range(1, 6):
        name = f"l{i}"
        aliases = ", ".join(f"*{prev}" for _ in range(10))
        lines.append(f"{name}: &{name}")
        lines.append(f"  <<: [{aliases}]")
        prev = name
    text = "---\n" + "\n".join(lines) + "\n---\nbody"
    with pytest.raises(FrontMatterError, match="merge key"):
        split_front_matter(text)


def test_oversized_front_matter_is_rejected() -> None:
    """Codex cross-review finding #2, part 3 (round 3, 2026-09-12): a size
    cap on the raw front-matter block, independent of merge-key handling."""
    text = "---\n" + ("x: " + "y" * 30_000 + "\n") + "---\nbody"
    with pytest.raises(FrontMatterError, match="exceeds"):
        split_front_matter(text)


def test_duplicate_key_in_a_mapping_is_rejected() -> None:
    """Regression for Codex#2 (round 12, 2026-09-13), reproduced exactly as
    reported: PyYAML silently keeps only the LAST value when a key is
    written twice in one mapping - a duplicated field can silently
    override an earlier, reviewed one with no error at all."""
    text = "---\nid: KU-0001\nclassification: public\nclassification: secret\n---\nbody"
    with pytest.raises(FrontMatterError, match="duplicate key"):
        split_front_matter(text)


def test_duplicate_key_in_a_nested_mapping_is_rejected() -> None:
    """The duplicate-key check must apply at every mapping level, not just
    the top-level front-matter mapping."""
    text = "---\nid: KU-0001\nnested:\n  a: 1\n  a: 2\n---\nbody"
    with pytest.raises(FrontMatterError, match="duplicate key"):
        split_front_matter(text)


def test_a_key_repeated_across_sibling_mappings_is_not_flagged() -> None:
    """The duplicate-key check is per-mapping, not global - the same key
    name legitimately appearing once in each of two unrelated mappings
    (e.g. two different nested blocks) is not a duplicate."""
    text = "---\nid: KU-0001\na:\n  x: 1\nb:\n  x: 2\n---\nbody"
    data, _ = split_front_matter(text)
    assert data == {"id": "KU-0001", "a": {"x": 1}, "b": {"x": 2}}
