# SPDX-License-Identifier: MIT
# Copyright (c) 2026 The remit contributors

.PHONY: demo test rules-json

demo:
	uv run demo

test:
	uv run pytest

# Regenerate the JSON mirror after editing requirements.yaml.
rules-json:
	uv run python -m remit.evidence.requirements
