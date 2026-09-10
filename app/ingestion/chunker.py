"""Split a Knowledge Unit body into sections for chunk-level retrieval."""

from __future__ import annotations

import re
from dataclasses import dataclass

_HEADING_RE = re.compile(r"^(#{1,6})\s+(.+?)\s*#*$")


@dataclass(frozen=True)
class Section:
    heading: str
    text: str


def split_sections(body: str) -> list[Section]:
    sections: list[Section] = []
    heading = ""
    buffer: list[str] = []

    def flush() -> None:
        text = "\n".join(buffer).strip()
        if text:
            sections.append(Section(heading, text))

    for line in body.splitlines():
        match = _HEADING_RE.match(line.strip())
        if match is not None:
            flush()
            heading = match.group(2).strip()
            buffer = []
        else:
            buffer.append(line)
    flush()
    return sections
