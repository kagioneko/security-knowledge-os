"""Classification gate and directory mapping (spec Section 9, decision A1).

Physical isolation by directory, logical label by front matter. ``secret`` is never
represented by a directory inside the repository.
"""

from __future__ import annotations

from app.config import Mode
from app.models.knowledge import Classification

# classification -> required path prefix relative to the knowledge root.
# ``None`` = must not exist inside the repository.
DIRECTORY_BY_CLASSIFICATION: dict[Classification, str | None] = {
    Classification.PUBLIC: "public",
    Classification.INTERNAL: "private/internal",
    Classification.CONFIDENTIAL: "private/confidential",
    Classification.SECRET: None,
}


class PolicyBlocked(Exception):
    """A classification rule was violated. Maps to the POLICY_BLOCKED outcome."""


def expected_relative_dir(classification: Classification) -> str:
    directory = DIRECTORY_BY_CLASSIFICATION[classification]
    if directory is None:
        raise PolicyBlocked(
            f"classification '{classification.value}' must not exist inside the repository"
        )
    return directory


def allowed_classifications(
    mode: Mode, allow_confidential: bool = False
) -> set[Classification]:
    if mode is Mode.PUBLIC:
        return {Classification.PUBLIC}
    allowed = {Classification.PUBLIC, Classification.INTERNAL}
    if allow_confidential:
        allowed.add(Classification.CONFIDENTIAL)
    return allowed


def is_retrievable(
    classification: Classification, mode: Mode, allow_confidential: bool = False
) -> bool:
    if classification is Classification.SECRET:
        return False
    return classification in allowed_classifications(mode, allow_confidential)


def assert_indexable(classification: Classification) -> None:
    """Guard called before writing anything to the retrieval index (AC-02)."""
    if classification is Classification.SECRET:
        raise PolicyBlocked("secret-classified knowledge must never be indexed")
