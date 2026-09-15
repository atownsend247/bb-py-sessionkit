"""Guards a deliberate design constraint: sessionkit stays framework-agnostic
and never imports an application it happens to be used from (e.g. `inventory`,
the app this package was originally extracted out of)."""

from __future__ import annotations

import ast
from pathlib import Path

import sessionkit

_FORBIDDEN_PREFIXES = ("inventory", "fastapi", "starlette", "pydantic")


def _imported_top_level_modules(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(), filename=str(path))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            names.add(node.module.split(".")[0])
    return names


def test_no_source_file_imports_inventory_or_a_web_framework():
    pkg_dir = Path(sessionkit.__file__).parent
    py_files = sorted(pkg_dir.rglob("*.py"))
    assert py_files, "expected to find sessionkit's source files"

    offenders: dict[str, set[str]] = {}
    for path in py_files:
        hits = _imported_top_level_modules(path) & set(_FORBIDDEN_PREFIXES)
        if hits:
            offenders[str(path.relative_to(pkg_dir.parent))] = hits

    assert not offenders, (
        "sessionkit must stay importable on its own - found forbidden imports: "
        f"{offenders}"
    )
