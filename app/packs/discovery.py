"""Find installed packs WITHOUT importing them.

Sources:
- the ``skos.packs`` entry-point group: only the metadata is read; the
  entry point's value names the pack's package, which is located through the
  distribution's recorded file list - ``ep.load()`` is never called.
- ``$SKOS_PACK_DIRS`` (``os.pathsep``-separated directories, each containing
  a ``pack.yaml``): for pack development. A pack found this way still needs a
  valid signature or an explicit ``skos packs enable``.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from importlib.metadata import entry_points
from pathlib import Path

from app.packs.manifest import MANIFEST_FILE

ENTRY_POINT_GROUP = "skos.packs"
_PACKAGE = r"^skos_pack_[a-z][a-z0-9]{1,15}$"


@dataclass(frozen=True)
class PackCandidate:
    label: str               # entry-point name, or the directory name for SKOS_PACK_DIRS
    directory: Path | None   # None when the pack could not be located
    source: str              # "entry-point:<dist>" or "SKOS_PACK_DIRS"
    problem: str | None = None


def _from_entry_points() -> list[PackCandidate]:
    found: list[PackCandidate] = []
    for ep in entry_points(group=ENTRY_POINT_GROUP):
        dist = ep.dist
        source = f"entry-point:{dist.metadata['Name'] if dist is not None else '?'}"
        package = ep.value.strip()
        if not re.fullmatch(_PACKAGE, package) or ep.name != package[len("skos_pack_") :]:
            found.append(
                PackCandidate(
                    ep.name, None, source,
                    "entry point must be `<name> = \"skos_pack_<name>\"`",
                )
            )
            continue
        files = (dist.files or []) if dist is not None else []
        manifests = [f for f in files if tuple(f.parts) == (package, MANIFEST_FILE)]
        if len(manifests) != 1 or dist is None:
            found.append(
                PackCandidate(
                    ep.name, None, source,
                    "pack.yaml not found in the installed files (editable install? "
                    "use SKOS_PACK_DIRS for development)",
                )
            )
            continue
        directory = Path(str(dist.locate_file(manifests[0]))).parent
        found.append(PackCandidate(ep.name, directory, source))
    return found


def _from_env() -> list[PackCandidate]:
    raw = os.environ.get("SKOS_PACK_DIRS", "")
    found: list[PackCandidate] = []
    for part in raw.split(os.pathsep):
        if not part:
            continue
        directory = Path(part)
        found.append(PackCandidate(directory.name, directory, "SKOS_PACK_DIRS"))
    return found


def discover() -> list[PackCandidate]:
    return _from_entry_points() + _from_env()
