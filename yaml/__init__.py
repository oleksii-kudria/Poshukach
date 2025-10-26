"""Minimal YAML parser for project configuration files."""

from __future__ import annotations

import ast
from typing import Any, Dict, List

__all__ = ["safe_load", "YAMLError"]


class YAMLError(Exception):
    """Generic YAML parsing error used for compatibility with PyYAML."""


def _parse_scalar(value: str) -> Any:
    value = value.strip()
    if not value:
        return ""
    if value.startswith(("\"", "'")) and value.endswith(("\"", "'")) and len(value) >= 2:
        return value[1:-1]
    return value


def _parse_inline(value: str) -> Any:
    value = value.strip()
    if not value:
        return ""
    if value.startswith("[") and value.endswith("]"):
        try:
            parsed = ast.literal_eval(value)
        except (SyntaxError, ValueError) as exc:  # pragma: no cover - defensive
            raise YAMLError(str(exc)) from exc
        if not isinstance(parsed, list):
            raise YAMLError("Inline YAML value must be a list")
        return [
            _parse_scalar(item) if isinstance(item, str) else item for item in parsed
        ]
    return _parse_scalar(value)


def safe_load(stream: Any) -> Any:
    if hasattr(stream, "read"):
        text = stream.read()
    else:
        text = stream

    if text is None:
        return None

    rules: List[Dict[str, Any]] = []
    root: Dict[str, Any] | None = None
    current_rule: Dict[str, Any] | None = None
    current_section: str | None = None

    for raw_line in str(text).splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        if stripped == "rules:":
            if root is None:
                root = {"rules": rules}
            continue

        if stripped.startswith("- mode:"):
            mode_value = stripped.split(":", 1)[1].strip()
            current_rule = {"mode": _parse_scalar(mode_value)}
            rules.append(current_rule)
            current_section = None
            continue

        if current_rule is None:
            raise YAMLError("Unexpected content outside of rule definition")

        if stripped.endswith(":") and not stripped.startswith("- "):
            key = stripped[:-1].strip()
            if key == "patterns":
                current_rule[key] = []
                current_section = "patterns"
            elif key in {"require", "except"}:
                current_rule[key] = {}
                current_section = key
            else:
                current_section = key
            continue

        if current_section == "patterns" and stripped.startswith("- "):
            value = stripped[2:]
            current_rule.setdefault("patterns", []).append(_parse_scalar(value))
            continue

        if current_section in {"require", "except"} and ":" in stripped:
            sub_key, value_str = stripped.split(":", 1)
            sub_key = sub_key.strip()
            current_rule[current_section][sub_key] = _parse_inline(value_str)
            continue

        raise YAMLError(f"Unsupported YAML structure: {stripped}")

    return root
