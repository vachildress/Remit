# SPDX-License-Identifier: MIT
# Copyright (c) 2026 The remit contributors
"""The tool table: which capability and level each tool needs, and the red lines."""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Any, Mapping

from ..evidence.model import Capability, Level
from ..evidence.requirements import yaml_available

PACKAGE = "remit.enforcement"


class ToolTableError(ValueError):
    pass


@dataclass(frozen=True)
class ToolSpec:
    name: str
    capability: Capability
    level: Level


@dataclass(frozen=True)
class ToolTable:
    tools: Mapping[str, ToolSpec]
    red_lines: Mapping[str, str]


def parse_tool_table(data: Mapping[str, Any]) -> ToolTable:
    data = {k: v for k, v in data.items() if not str(k).startswith("_")}
    extra = set(data) - {"version", "tools", "red_lines"}
    if extra:
        raise ToolTableError(f"unknown top level fields: {', '.join(sorted(extra))}")
    tools = {}
    for name, spec in (data.get("tools") or {}).items():
        spec = spec or {}
        unknown = set(spec) - {"capability", "level"}
        if unknown:
            raise ToolTableError(f"tool {name}: unknown fields {', '.join(sorted(unknown))}")
        try:
            cap = Capability(spec.get("capability"))
            level = Level(spec.get("level"))
        except ValueError as exc:
            raise ToolTableError(f"tool {name}: {exc}") from exc
        if level is Level.NONE:
            raise ToolTableError(f"tool {name}: a tool needing level none needs no grant; use limited or full")
        tools[name] = ToolSpec(name, cap, level)
    red_lines = {str(k): str(v) for k, v in (data.get("red_lines") or {}).items()}
    both = set(tools) & set(red_lines)
    if both:
        raise ToolTableError(f"listed both as a tool and as a red line: {', '.join(sorted(both))}")
    return ToolTable(tools, red_lines)


def bundled_text(fmt: str) -> str:
    return resources.files(PACKAGE).joinpath(f"tools.{fmt}").read_text()


def load_tool_table(path: str | Path | None = None, *, fmt: str | None = None) -> ToolTable:
    if path is None:
        fmt = fmt or ("yaml" if yaml_available() else "json")
        text = bundled_text(fmt)
    else:
        path = Path(path)
        fmt = fmt or ("json" if path.suffix == ".json" else "yaml")
        text = path.read_text()
    if fmt == "json":
        return parse_tool_table(json.loads(text))
    import yaml

    return parse_tool_table(yaml.safe_load(text))


JSON_HEADER = {
    "_licence": "SPDX-License-Identifier: MIT. Copyright (c) 2026 The remit contributors.",
    "_generated": "Generated from tools.yaml by 'make rules-json'. Do not edit by hand.",
}


def export_json() -> str:
    import yaml

    data = yaml.safe_load(bundled_text("yaml"))
    return json.dumps({**JSON_HEADER, **data}, indent=2) + "\n"


def main() -> int:
    target = Path(__file__).with_name("tools.json")
    text = export_json()
    parse_tool_table(json.loads(text))
    target.write_text(text)
    print(f"wrote {target}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
