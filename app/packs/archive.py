"""Read an Update Pack ZIP into memory WITHOUT extracting it.

Every entry is checked before its content is read (spec section 7 step 1,
section 13): no absolute paths, no ``..``, no backslashes, no symlinks, no
duplicates, no encryption, only the allowlisted data files of pack API 1, and
hard caps on entry count and on the decompressed size of every entry and of
the whole pack (declared sizes are not trusted - reads are bounded).
"""

from __future__ import annotations

import io
import stat
import zipfile
import zlib
from pathlib import Path

from app.packs.manifest import allowed_pack_path

MAX_ZIP_BYTES = 20_000_000
MAX_ENTRIES = 1_000
MAX_ENTRY_BYTES = 1_000_000
MAX_TOTAL_BYTES = 20_000_000
_ALLOWED_METHODS = {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}


class PackArchiveError(ValueError):
    """The ZIP is not a safe, well-formed pack archive."""


def _entry_problem(info: zipfile.ZipInfo) -> str | None:
    name = info.filename
    if not name or name.startswith("/") or "\\" in name or "\0" in name:
        return "absolute or malformed path"
    if len(name) >= 2 and name[1] == ":":
        return "drive-qualified path"
    if any(part in ("", ".", "..") for part in name.rstrip("/").split("/")):
        return "'..' or empty path segment"
    mode = info.external_attr >> 16
    if stat.S_ISLNK(mode):
        return "symlink entry"
    if info.flag_bits & 0x41:  # bit 0 traditional / bit 6 strong encryption
        return "encrypted entry"
    if info.compress_type not in _ALLOWED_METHODS:
        return "unsupported compression method"
    if info.is_dir():
        return None if name == "rules/" else "unexpected directory"
    if not allowed_pack_path(name):
        return "file type/location not allowed in a pack (data files only)"
    return None


def read_zip_bytes(path: Path) -> bytes:
    """Read the archive once, bounded. Callers verify and store these exact
    bytes, so the file cannot change between verification and installation."""
    try:
        with path.open("rb") as fh:
            data = fh.read(MAX_ZIP_BYTES + 1)
    except OSError as exc:
        raise PackArchiveError(f"cannot read pack ({type(exc).__name__})") from None
    if len(data) > MAX_ZIP_BYTES:
        raise PackArchiveError(f"pack ZIP exceeds {MAX_ZIP_BYTES} bytes")
    return data


def read_pack_zip(data: bytes) -> dict[str, bytes]:
    """Return ``{path: bytes}`` for every file entry of the archive in
    ``data``. Raises ``PackArchiveError`` on the first unsafe entry; messages
    name the entry only when it passed the path checks."""
    if len(data) > MAX_ZIP_BYTES:
        raise PackArchiveError(f"pack ZIP exceeds {MAX_ZIP_BYTES} bytes")
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except (zipfile.BadZipFile, OSError, NotImplementedError, ValueError):
        raise PackArchiveError("not a valid ZIP file") from None
    files: dict[str, bytes] = {}
    total = 0
    with zf:
        infos = zf.infolist()
        if len(infos) > MAX_ENTRIES:
            raise PackArchiveError(f"more than {MAX_ENTRIES} entries")
        for index, info in enumerate(infos):
            problem = _entry_problem(info)
            if problem is not None:
                raise PackArchiveError(f"entry #{index + 1}: {problem}")
            if info.is_dir():
                continue
            if info.filename in files:
                raise PackArchiveError(f"duplicate entry {info.filename}")
            try:
                with zf.open(info) as fh:
                    data = fh.read(MAX_ENTRY_BYTES + 1)
            except (
                zipfile.BadZipFile, OSError, EOFError, ValueError, zlib.error,
                NotImplementedError,  # a ZIP feature the reader does not support
            ):
                raise PackArchiveError(f"{info.filename}: corrupt entry") from None
            if len(data) > MAX_ENTRY_BYTES:
                raise PackArchiveError(f"{info.filename}: exceeds {MAX_ENTRY_BYTES} bytes")
            total += len(data)
            if total > MAX_TOTAL_BYTES:
                raise PackArchiveError(f"pack content exceeds {MAX_TOTAL_BYTES} bytes")
            files[info.filename] = data
    return files
