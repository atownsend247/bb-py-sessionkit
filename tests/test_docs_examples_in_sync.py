"""docs/integration.md embeds examples/fastapi_app.py verbatim between
`<!-- BEGIN examples/fastapi_app.py -->` / `<!-- END -->` markers. This fails
loudly if someone edits one copy and not the other, instead of letting the
published example quietly rot - see docs/development.md#keeping-the-example-honest.
"""

from __future__ import annotations

import re
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_MARKER_RE = re.compile(
    r"<!-- BEGIN examples/fastapi_app\.py -->\n```python\n(.*?)\n```\n<!-- END examples/fastapi_app\.py -->",
    re.DOTALL,
)


def test_fastapi_example_in_docs_matches_the_source_file():
    doc = (_ROOT / "docs" / "integration.md").read_text()
    match = _MARKER_RE.search(doc)
    assert match is not None, (
        "docs/integration.md is missing the "
        "<!-- BEGIN/END examples/fastapi_app.py --> markers, or something "
        "inside them no longer parses as a single python code fence"
    )
    embedded = match.group(1)
    source = (_ROOT / "examples" / "fastapi_app.py").read_text().rstrip("\n")

    assert embedded == source, (
        "docs/integration.md's embedded copy of examples/fastapi_app.py is "
        "out of date. Edit examples/fastapi_app.py, then copy its exact "
        "contents back into the <!-- BEGIN/END --> block in docs/integration.md."
    )
