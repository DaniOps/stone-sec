from pathlib import Path
from typing import List

EXCLUDED_DIRS = {
    ".venv",
    "venv",
    "__pycache__",
    "site-packages",
}


def discover_python_files(target: Path) -> List[Path]:
    """
    Discover Python files from a file or directory path,
    excluding virtual environments and dependencies.
    """

    python_files: List[Path] = []

    if target.is_file():
        if target.suffix == ".py":
            return [target.resolve()]
        return []

    if target.is_dir():
        for path in target.rglob("*.py"):
            # Skip excluded directories
            if any(part in EXCLUDED_DIRS for part in path.parts):
                continue

            if path.is_file():
                python_files.append(path.resolve())

    python_files.sort()
    return python_files