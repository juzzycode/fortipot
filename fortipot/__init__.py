"""fortipot package."""

from __future__ import annotations

import os
import subprocess
from functools import lru_cache
from pathlib import Path

__all__ = ["__version__", "__version_base__", "get_version"]

__version_base__ = "0.1.0"


@lru_cache(maxsize=1)
def get_version() -> str:
    """Return the base version plus a build number when available."""

    build_number = os.getenv("FORTIPOT_BUILD_NUMBER") or _git_commit_count()
    if build_number:
        return f"{__version_base__}.{build_number}"
    return __version_base__


def _git_commit_count() -> str | None:
    """Return the current repository commit count."""

    repo_root = Path(__file__).resolve().parent.parent
    try:
        result = subprocess.run(
            ["git", "rev-list", "--count", "HEAD"],
            cwd=repo_root,
            capture_output=True,
            check=True,
            text=True,
            timeout=2,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    count = result.stdout.strip()
    return count if count.isdigit() else None


__version__ = get_version()
