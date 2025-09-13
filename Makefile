# ShadowScan - Makefile for Development Tasks
# Usage: make [target]

# Variables
PYTHON ?= python
VENV_DIR ?= venv
PACKAGE_NAME = shadowscan
TEST_DIR = tests
REPORT_DIR = reports

# Default target
all: help

# Help
help:
	@echo "\nShadowScan - Universal Cyber Attack Test Engine\n"
	@echo "Development targets:"
	@echo "  install        Install dependencies in virtual environment"
	@echo "  dev            Setup development environment"
	@echo "  test           Run tests"
	@echo "  lint           Run linters"
	@echo "  format         Format code"
	@echo "  docs           Build documentation"
	@echo "  security       Run security checks"
	@echo "  report         Generate security report"
	@echo "  clean          Clean build artifacts"
	@echo ""

# Setup development environment
dev: install
	$(PYTHON) -m pip install -e .[dev,docs,tenderly]

# Install dependencies
install:
	$(PYTHON) -m venv $(VENV_DIR)
	. $(VENV_DIR)/bin/activate && \
	$(PYTHON) -m pip install --upgrade pip && \
	$(PYTHON) -m pip install -r requirements.txt

# Run tests
test:
	. $(VENV_DIR)/bin/activate && \
	$(PYTHON) -m pytest $(TEST_DIR) --cov=$(PACKAGE_NAME) --cov-report=term-missing

# Run linters
lint:
	. $(VENV_DIR)/bin/activate && \
	black --check $(PACKAGE_NAME) $(TEST_DIR) && \
	isort --check $(PACKAGE_NAME) $(TEST_DIR) && \
	flake8 $(PACKAGE_NAME) $(TEST_DIR) && \
	mypy $(PACKAGE_NAME)

# Format code
format:
	. $(VENV_DIR)/bin/activate && \
	black $(PACKAGE_NAME) $(TEST_DIR) && \
	isort $(PACKAGE_NAME) $(TEST_DIR)

# Build documentation
docs:
	. $(VENV_DIR)/bin/activate && \
	sphinx-build -b html docs $(REPORT_DIR)/docs

# Run security checks
security:
	. $(VENV_DIR)/bin/activate && \
	bandit -r $(PACKAGE_NAME) -c .bandit.yml && \
	safety check --full-report

# Generate security report
report:
	. $(VENV_DIR)/bin/activate && \
	$(PYTHON) -m pytest --cov=$(PACKAGE_NAME) --cov-report=html && \
	bandit -r $(PACKAGE_NAME) -f html -o $(REPORT_DIR)/bandit.html && \
	safety check --output=$(REPORT_DIR)/safety.txt

# Clean build artifacts
clean:
	rm -rf build dist *.egg-info
	rm -rf $(REPORT_DIR)/*.html $(REPORT_DIR)/*.txt
	rm -rf .tox .pytest_cache .mypy_cache
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.py[co]" -exec rm -f {} +

# Phony targets
.PHONY: all help install dev test lint format docs security report clean
