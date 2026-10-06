# Development tasks. Everything here runs offline: no API key, no network, no GPU.
.PHONY: help install check lint format types test bench bench-external demo evidence all

help:
	@echo "install   editable install with dev extras"
	@echo "check     lint, format check, types, tests  (what CI runs)"
	@echo "bench     the benchmark table"
	@echo "bench-external  score against MCPTox; fetches once, then offline"
	@echo "demo      the gateway against the hostile example server"
	@echo "evidence  regenerate assets/ from a live run"

install:
	python -m pip install -e ".[dev]"

lint:
	ruff check .

format:
	ruff format .

types:
	mypy

test:
	pytest -q

bench:
	python evaluation/benchmark.py

# The only target that touches the network, and only on a cold cache.
bench-external:
	python -m evaluation.external

demo:
	python -m mcp_policy_gateway.cli demo

evidence:
	python evaluation/make_evidence.py

check: lint types test bench
	ruff format --check .

all: check demo
