"""Split a Knowledge Unit Markdown file into YAML front matter + body."""

from __future__ import annotations

import errno
import os
import re
import stat
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


class _LoaderRefusal(yaml.constructor.ConstructorError):
    """A refusal this module raises itself, with a message written here and
    containing nothing from the document (no key name, no scalar). Unlike
    PyYAML's own errors - whose text can quote source content - it is safe
    to show verbatim (see `_describe_yaml_error`)."""

    def __init__(self, safe_message: str, mark: yaml.Mark) -> None:
        super().__init__(None, None, safe_message, mark)
        self.safe_message = safe_message


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

    Codex#2 (round 12, 2026-09-13), reproduced exactly as reported: PyYAML
    (like the YAML 1.1 spec's own "should" rather than "must") silently
    keeps only the LAST value when the same key is written twice in one
    mapping - a duplicated ``severity``/``conditions``/``checks`` field can
    silently weaken a reviewed rule with no error at all. Checked here, on
    the raw key NODES, for the same reason the merge-key check above is:
    this runs once per mapping, before any value is actually constructed,
    so a later sibling with the same key is rejected before it can
    overwrite anything.
    """

    def flatten_mapping(self, node: yaml.MappingNode) -> None:
        seen_keys: set[tuple[str, str]] = set()
        for key_node, _value_node in node.value:
            if key_node.tag == "tag:yaml.org,2002:merge":
                raise _LoaderRefusal(
                    "merge keys ('<<') are not allowed in front matter", key_node.start_mark
                )
            if isinstance(key_node, yaml.ScalarNode):
                key_id = (key_node.tag, key_node.value)
                if key_id in seen_keys:
                    # The key's NAME is deliberately not in the message (it is
                    # attacker-chosen text and could itself be a secret); the
                    # position identifies it.
                    raise _LoaderRefusal("duplicate key in mapping", key_node.start_mark)
                seen_keys.add(key_id)
        super().flatten_mapping(node)


def read_text_bounded(path: Path, *, max_bytes: int, what: str = "file") -> str:
    """Read at most ``max_bytes`` + 1 bytes and reject the file before
    decoding if it is larger.

    Codex#4 (round 23, 2026-09-20), reproduced exactly as reported: the CLI
    loaders called ``Path.read_text()`` and only THEN handed the string to
    ``safe_load_bounded()``, whose size limit therefore bounded the parse,
    not the read - a multi-gigabyte (or sparse) assessment file was fully
    loaded into memory, and encoded a second time for the length check,
    before the 500 KB cap was ever consulted. A FIFO/`/dev/stdin` input
    still works: the read is bounded regardless of the file type. Raises
    ``FrontMatterError`` when over the limit; ``OSError`` /
    ``UnicodeDecodeError`` propagate exactly as ``read_text()``'s did, so
    existing callers' handling is unchanged."""
    with open(path, "rb") as fh:
        data = fh.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise FrontMatterError(f"{what} exceeds {max_bytes} bytes")
    return data.decode("utf-8")


def _describe_yaml_error(exc: yaml.YAMLError) -> str:
    """Error class and position only. PyYAML's own `str(exc)` embeds a
    snippet of the offending source line (and `problem` can quote an alias
    or tag name), so a secret sitting on the line that failed to parse was
    echoed to stderr / the HTTP response. Reproduced: an unterminated quoted
    string `description: "AKIA...` printed the whole line."""
    problem = getattr(exc, "problem_mark", None)
    context = getattr(exc, "context_mark", None)
    parts = []
    if problem is not None:
        parts.append(f"at line {problem.line + 1}, column {problem.column + 1}")
    if context is not None:
        # e.g. an unterminated quoted scalar: `problem` is the end of the
        # stream, `context` is where the scalar STARTED - the useful one.
        parts.append(f"construct started at line {context.line + 1}, column {context.column + 1}")
    detail = f": {exc.safe_message}" if isinstance(exc, _LoaderRefusal) else ""
    return " ".join([type(exc).__name__, *parts]) + detail


def safe_load_bounded(text: str, *, max_bytes: int, what: str = "YAML content") -> Any:
    """A size-capped ``yaml.load`` using ``_RestrictedSafeLoader`` (merge
    keys refused) that converts every way PyYAML can blow up on hostile
    input into ``FrontMatterError``, never a raw exception.

    Codex#5 (round 7, 2026-09-12), reproduced exactly as reported: rule and
    safe-test YAML files had none of these protections at all - only
    knowledge front matter did (round 2/3, Codex#8/#2). Roughly 1,500
    nested YAML collections raised an uncaught ``RecursionError`` straight
    out of both loaders. Shared here so every YAML boundary in this app -
    front matter, rules, safe tests - has the same protections and cannot
    independently regress.
    """
    if len(text.encode("utf-8", errors="replace")) > max_bytes:
        raise FrontMatterError(f"{what} exceeds {max_bytes} bytes")
    try:
        return yaml.load(text, Loader=_RestrictedSafeLoader)
    except yaml.YAMLError as exc:
        # Codex round-31 (2026-09-25), reproduced exactly as reported:
        # _describe_yaml_error() exists specifically because PyYAML's own
        # str(exc) embeds a snippet of the offending source line (see its
        # docstring) - but `from exc` kept that raw exception as __cause__
        # regardless, so any traceback dump of the chain (server logs, an
        # unhandled-exception handler) leaked the very content this
        # sanitized message was built to avoid. `from None` drops it.
        raise FrontMatterError(f"invalid YAML in {what}: {_describe_yaml_error(exc)}") from None
    except ValueError as exc:
        # Codex cross-review finding #8 (round 2, 2026-09-11): a
        # syntactically-shaped but semantically invalid scalar (e.g. the
        # timestamp "2026-99-99" - matches PyYAML's timestamp regex, but
        # month=99 fails datetime construction) raises a bare ValueError from
        # the resolver/constructor, not a yaml.YAMLError subclass - it was
        # not caught here, and POST /v1/knowledge/validate (meant to always
        # return a clean {valid: false, errors: [...]} response for exactly
        # this kind of bad input) returned an HTTP 500 instead.
        # Codex#3 (round 23 follow-up, 2026-09-20): the message of a constructor
        # ValueError can quote the scalar it choked on (`int()`'s "invalid
        # literal ... 'AKIA...'"), so only the exception type is reported.
        # Codex round-31 (2026-09-25): `from exc` kept that same quoting
        # exception reachable as __cause__ despite the message above
        # deliberately omitting it - same fix as the YAMLError branch.
        raise FrontMatterError(f"invalid value in {what} ({type(exc).__name__})") from None
    except RecursionError as exc:
        # Codex cross-review finding #2, part 2 (round 3, 2026-09-12): a
        # small document with hundreds of nested flow collections
        # (`[[[[...]]]]`) drives PyYAML's recursive-descent composer past
        # Python's recursion limit. That is not a YAMLError subclass either,
        # so it also escaped as an HTTP 500 instead of a controlled
        # {valid: false} response.
        raise FrontMatterError(f"{what} is too deeply nested") from exc


def split_front_matter(text: str) -> tuple[dict[str, Any], str]:
    match = _FRONT_MATTER_RE.match(text.lstrip("﻿"))
    if match is None:
        raise FrontMatterError(
            "missing or malformed YAML front matter (expected a leading '---' block)"
        )
    data = safe_load_bounded(
        match.group("fm"), max_bytes=_MAX_FRONT_MATTER_BYTES, what="front matter"
    )
    if not isinstance(data, dict):
        raise FrontMatterError("front matter must be a YAML mapping")
    return data, match.group("body")


def _read_text_no_follow(path: Path) -> str:
    """Codex#5 (round 6, 2026-09-12), reproduced exactly as reported: the
    symlink/containment check (`is_symlink()`/`resolve()`) and this file's
    actual read used to be two separate filesystem operations on the same
    PATHNAME, with a window between them - fault injection that validated
    an ordinary in-root file, swapped it to an outside-root symlink right
    before the read, then restored the original file before any later
    check ran, made ``load_corpus()`` read straight through the outside
    file. Opening with ``O_NOFOLLOW`` makes the read itself fail (ELOOP) if
    ``path`` names a symlink at the moment of the open, regardless of what
    an earlier or later check by the same pathname would have seen.
    """
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise FrontMatterError(
                f"{path}: became a symlink between an earlier check and this read "
                "(refusing - symlinked Knowledge Unit files are not allowed)"
            ) from exc
        raise
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise FrontMatterError(f"{path}: not a regular file")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            chunks.append(chunk)
        try:
            return b"".join(chunks).decode("utf-8")
        except UnicodeDecodeError as exc:
            # Codex#5 (round 7, 2026-09-12), reproduced exactly as reported:
            # invalid UTF-8 in a KU raised a raw UnicodeDecodeError out of
            # reindex_atomic() instead of a typed POLICY_BLOCKED/validation
            # error - the API received a 500 rather than a clean rejection.
            raise FrontMatterError(f"{path}: not valid UTF-8: {exc}") from exc
    finally:
        os.close(fd)


def read_markdown(path: Path) -> tuple[dict[str, Any], str]:
    return split_front_matter(_read_text_no_follow(path))
