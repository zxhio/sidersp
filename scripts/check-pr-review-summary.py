#!/usr/bin/env python3

from __future__ import annotations

import pathlib
import re
import sys


REQUIRED_FIELDS = ("Scope", "Specs", "Verify", "Verdict", "Risk")
ALLOWED_VERDICTS = {"ready", "ready with risk", "blocked"}
PLACEHOLDER_MARKERS = ("<", "todo", "tbd", "fill", "_no response_")


def fail(message: str) -> None:
    print(f"pr-review-summary: {message}", file=sys.stderr)
    raise SystemExit(1)


def main() -> None:
    if len(sys.argv) != 2:
        fail("usage: python3 scripts/check-pr-review-summary.py <body-file>")

    body = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
    match = re.search(r"(?ms)^## AI Review\s*(.*?)(?=^##\s|\Z)", body)
    if not match:
        fail("missing '## AI Review' section")

    section = match.group(1)
    values: dict[str, str] = {}
    errors: list[str] = []

    for field in REQUIRED_FIELDS:
        field_match = re.search(rf"^- {field}:\s*(.+)$", section, re.MULTILINE)
        if not field_match:
            errors.append(f"missing '- {field}:' line")
            continue

        value = field_match.group(1).strip()
        if not value:
            errors.append(f"empty '{field}' value")
            continue

        lower_value = value.lower()
        if any(marker in lower_value for marker in PLACEHOLDER_MARKERS):
            errors.append(f"placeholder left in '{field}' value")
            continue

        values[field] = value

    verdict = values.get("Verdict", "").lower()
    if verdict and verdict not in ALLOWED_VERDICTS:
        errors.append("invalid 'Verdict' value; use Ready, Ready with risk, or Blocked")

    if errors:
        fail("; ".join(errors))

    print("pr-review-summary: ok")


if __name__ == "__main__":
    main()
