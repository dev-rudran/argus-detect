PYTHON ?= python
RUFF ?= ruff
BANDIT ?= bandit
PYTEST ?= python -m pytest

.PHONY: install test lint format format-check bandit check clean

install:
	$(PYTHON) -m pip install -e ".[dev]"

test:
	$(PYTEST)

lint:
	$(RUFF) check .

format:
	$(RUFF) format .

format-check:
	$(RUFF) format --check .

bandit:
	$(BANDIT) -r src

check: lint format-check bandit test

clean:
	rm -rf build dist .pytest_cache .ruff_cache .coverage htmlcov
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
	find . -type d -name '*.egg-info' -prune -exec rm -rf {} +
