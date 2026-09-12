"""Split a Knowledge Unit Markdown file into YAML front matter + body."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

_FRONT_MATTER_RE = re.compile(
    r"\A---[ \t]*\r?\n(?P<fm>.*?)\r?\n---[ \t]*\r?\n(?P<body>.*)\Z",
    re.DOTALL,
)

# Codex cross-review finding #2 (round 3, 2026-09-12): front matter is a flat,
# hand-authored key/value block (id/title/category/... - see
# KnowledgeUnitFrontMatter); real ones are a few hundred bytes. This bounds
# the raw text handed to the YAML parser regardless of *how* it would blow up,
# on top of the merge-key ban below.
_MAX_FRONT_MATTER_BYTES = 20_000


class FrontMatterError(ValueError):
    """The file has no parseable YAML front matter block."""


class _RestrictedSafeLoader(yaml.SafeLoader):
    """SafeLoader with YAML merge keys (``<<``) refused outright.

    Codex cross-review finding #2 (round 3, 2026-09-12): ``yaml.safe_load``
    blocks arbitrary Python object construction, but not a "billion laughs"
    style blow-up: a mapping merge (``<<: *anchor``) copies the *values* of
    the merged-in mapping into the new one, so chaining N mappings that each
    merge the same handful of aliases together multiplies the materialized
    size at every level. A 285-byte document was observed expanding past
    100,000 mapping pairs this way. Front matter is a flat mapping of scalar
    fields and never legitimately needs anchors or merge keys, so merge keys
    are refused rather than resolved; plain aliases (which share, not copy,
    the referenced object) are left alone as harmless.

    Merge-key handling in ``SafeConstructor.flatten_mapping()`` special-cases
    the ``tag:yaml.org,2002:merge`` tag directly (splicing the merged pairs
    into ``node.value``) *before* any constructor dispatch happens - it never
    calls ``construct_object`` on the merge-tagged node, so registering a
    constructor for that tag (the usual way to override YAML behaviour) has
    no effect here. ``flatten_mapping`` itself must be overridden instead.
    """

    def flatten_mapping(self, node: yaml.MappingNode) -> None:
        for key_node, _value_node in node.value:
            if key_node.tag == "tag:yaml.org,2002:merge":
                raise yaml.constructor.ConstructorError(
                    None,
                    None,
                    "merge keys ('<<') are not allowed in front matter",
                    key_node.start_mark,
                )
        super().flatten_mapping(node)


def split_front_matter(text: str) -> tuple[dict[str, Any], str]:
    match = _FRONT_MATTER_RE.match(text.lstrip("﻿"))
    if match is None:
        raise FrontMatterError(
            "missing or malformed YAML front matter (expected a leading '---' block)"
        )
    raw_front_matter = match.group("fm")
    if len(raw_front_matter.encode("utf-8", errors="replace")) > _MAX_FRONT_MATTER_BYTES:
        raise FrontMatterError(
            f"front matter exceeds {_MAX_FRONT_MATTER_BYTES} bytes"
        )
    try:
        data = yaml.load(raw_front_matter, Loader=_RestrictedSafeLoader)
    except yaml.YAMLError as exc:
        raise FrontMatterError(f"invalid YAML in front matter: {exc}") from exc
    except ValueError as exc:
        # Codex cross-review finding #8 (round 2, 2026-09-11): a
        # syntactically-shaped but semantically invalid scalar (e.g. the
        # timestamp "2026-99-99" - matches PyYAML's timestamp regex, but
        # month=99 fails datetime construction) raises a bare ValueError from
        # the resolver/constructor, not a yaml.YAMLError subclass - it was
        # not caught here, and POST /v1/knowledge/validate (meant to always
        # return a clean {valid: false, errors: [...]} response for exactly
        # this kind of bad input) returned an HTTP 500 instead.
        raise FrontMatterError(f"invalid value in front matter: {exc}") from exc
    except RecursionError as exc:
        # Codex cross-review finding #2, part 2 (round 3, 2026-09-12): a
        # small document with hundreds of nested flow collections
        # (`[[[[...]]]]`) drives PyYAML's recursive-descent composer past
        # Python's recursion limit. That is not a YAMLError subclass either,
        # so it also escaped as an HTTP 500 instead of a controlled
        # {valid: false} response.
        raise FrontMatterError("front matter is too deeply nested") from exc
    if not isinstance(data, dict):
        raise FrontMatterError("front matter must be a YAML mapping")
    return data, match.group("body")


def read_markdown(path: Path) -> tuple[dict[str, Any], str]:
    return split_front_matter(path.read_text(encoding="utf-8"))
