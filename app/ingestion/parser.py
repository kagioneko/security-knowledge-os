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


class FrontMatterError(ValueError):
    """The file has no parseable YAML front matter block."""


def split_front_matter(text: str) -> tuple[dict[str, Any], str]:
    match = _FRONT_MATTER_RE.match(text.lstrip("﻿"))
    if match is None:
        raise FrontMatterError(
            "missing or malformed YAML front matter (expected a leading '---' block)"
        )
    try:
        data = yaml.safe_load(match.group("fm"))
    except yaml.YAMLError as exc:
        raise FrontMatterError(f"invalid YAML in front matter: {exc}") from exc
    if not isinstance(data, dict):
        raise FrontMatterError("front matter must be a YAML mapping")
    return data, match.group("body")


def read_markdown(path: Path) -> tuple[dict[str, Any], str]:
    return split_front_matter(path.read_text(encoding="utf-8"))
