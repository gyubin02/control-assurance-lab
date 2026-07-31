#!/usr/bin/env python3
"""Remove only BuildKit's empty local-content-store ingest workspace."""

from __future__ import annotations

import argparse
import os
import stat
from pathlib import Path


class LayoutRejectedError(ValueError):
    """The BuildKit output cannot be reduced to a closed OCI layout."""


def canonicalize(layout: Path) -> None:
    """Remove ``ingest`` only when both paths are real directories and it is empty."""

    try:
        layout_mode = layout.lstat().st_mode
    except FileNotFoundError as error:
        raise LayoutRejectedError(f"layout directory does not exist: {layout}") from error
    if not stat.S_ISDIR(layout_mode):
        raise LayoutRejectedError(f"layout path is not a directory: {layout}")

    ingest = layout / "ingest"
    try:
        ingest_mode = ingest.lstat().st_mode
    except FileNotFoundError as error:
        raise LayoutRejectedError(
            f"expected BuildKit ingest directory is missing: {ingest}"
        ) from error
    if not stat.S_ISDIR(ingest_mode):
        raise LayoutRejectedError(
            f"BuildKit ingest path is not a real directory: {ingest}"
        )

    with os.scandir(ingest) as entries:
        if next(entries, None) is not None:
            raise LayoutRejectedError(
                f"BuildKit ingest directory is not empty: {ingest}"
            )

    # This is the final emptiness check: rmdir fails atomically if a writer
    # creates an entry after the scan.
    os.rmdir(ingest)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Remove BuildKit's empty containerd ingest workspace before strict "
            "OCI-layout verification."
        )
    )
    parser.add_argument("layout", type=Path, help="BuildKit OCI directory output")
    arguments = parser.parse_args()

    try:
        canonicalize(arguments.layout)
    except (LayoutRejectedError, OSError) as error:
        parser.exit(1, f"layout canonicalization rejected: {error}\n")

    print(f"Removed empty BuildKit ingest workspace: {arguments.layout / 'ingest'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
