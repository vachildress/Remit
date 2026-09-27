# SPDX-License-Identifier: MIT
# Copyright (c) 2026 The remit contributors

.PHONY: demo test

demo:
	uv run demo

test:
	uv run pytest
