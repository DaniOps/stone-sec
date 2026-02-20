import ast
from pathlib import Path
from typing import Optional


def parse_python_file(path: Path) -> Optional[ast.AST]:
    """
    Safely parse a Python file into an AST.

    Returns:
        ast.AST if parsing succeeds
        None if file contains syntax errors or cannot be read
    """
    try:
        source = path.read_text(encoding="utf-8")
        return ast.parse(source, filename=str(path))
    except (SyntaxError, UnicodeDecodeError, OSError):
        # We never crash on bad files
        return None