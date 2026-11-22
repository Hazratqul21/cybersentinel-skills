PYTHON ?= python3

.PHONY: help validate test lint install-dev clean list

help:
	@echo "CyberSentinel Skills — make targets"
	@echo "  make validate    Validate all skills (stdlib only, no deps)"
	@echo "  make test        Run the test suite (unittest; pytest if available)"
	@echo "  make list        List discovered skills"
	@echo "  make install-dev Editable install with dev extras"
	@echo "  make clean       Remove caches"

validate:
	PYTHONPATH=src $(PYTHON) -m cybersentinel validate

list:
	PYTHONPATH=src $(PYTHON) -m cybersentinel list

test:
	@if $(PYTHON) -c "import pytest" 2>/dev/null; then \
		PYTHONPATH=src $(PYTHON) -m pytest -q; \
	else \
		echo "pytest not found; running stdlib unittest"; \
		PYTHONPATH=src $(PYTHON) -m unittest discover -s tests -v; \
	fi

install-dev:
	$(PYTHON) -m pip install -e ".[dev]"

clean:
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
	rm -rf .pytest_cache src/*.egg-info build dist
