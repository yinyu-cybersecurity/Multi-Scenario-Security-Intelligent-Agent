PYTHON ?= python
PIP ?= $(PYTHON) -m pip
PYTEST ?= $(PYTHON) -m pytest

.PHONY: help install install-dev run-web run-cli verify lint format test test-fast security ci

help:
	@echo "Available targets:"
	@echo "  make install      - Install runtime dependencies"
	@echo "  make install-dev  - Install runtime + development dependencies"
	@echo "  make run-web      - Start the Flask web service"
	@echo "  make run-cli      - Show CLI entrypoint help"
	@echo "  make verify       - Run repository verification script"
	@echo "  make lint         - Run formatting and lint checks"
	@echo "  make format       - Apply formatting"
	@echo "  make test         - Run the full test suite"
	@echo "  make test-fast    - Run the current fast regression subset"
	@echo "  make security     - Run static security checks"
	@echo "  make ci           - Run lint + test + security"

install:
	$(PIP) install -r requirements.txt

install-dev:
	$(PIP) install -r requirements.txt
	$(PIP) install pytest pytest-cov black isort ruff bandit pip-audit networkx matplotlib pyvis

run-web:
	$(PYTHON) web/api.py

run-cli:
	$(PYTHON) app/ctf_agent_graph.py --help

verify:
	$(PYTHON) verify_system.py

lint:
	black --check .
	isort --check-only .
	ruff check .

format:
	black .
	isort .

test:
	$(PYTEST) tests/ -v --tb=short

test-fast:
	$(PYTEST) tests/test_tool_framework.py tests/test_state_types.py -q

security:
	bandit -q -r app web remote_executor internal_network tools
	pip-audit

ci: lint test security
