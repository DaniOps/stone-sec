from pathlib import Path
from typing import List


def discover_python_files(target: Path) -> List[Path]:
    """
    Discover Python files from a file or directory path.

    - If target is a .py file → return [target]
    - If target is a directory → recursively return all .py files
    - Returns absolute Path objects
    """

    python_files: List[Path] = []

    if target.is_file():
        if target.suffix == ".py":
            python_files.append(target.resolve())
        return python_files

    if target.is_dir():
        for path in target.rglob("*.py"):
            # Skip non-files just in case
            if path.is_file():
                python_files.append(path.resolve())

    # Deterministic order (important for CI reproducibility)
    python_files.sort()

    return python_files