# Token in Query Params - Automation Makefile

# Variables
DOCKER_COMPOSE = docker-compose
PYTHON = python
PIP = pip
PYTEST = pytest
RUST_TOOL = tools/log_auditor

.PHONY: all help build up down logs test clean forensics redo-env

all: build up test forensics

help:
	@echo "--- Token in Query Params Project Automation ---"
	@echo "Usage:"
	@echo "  make build          - Build Docker containers"
	@echo "  make up             - Start Docker containers"
	@echo "  make down           - Stop Docker containers"
	@echo "  make logs           - View container logs"
	@echo "  make test           - Run security audit tests"
	@echo "  make clean          - Remove logs and caches"
	@echo "  make forensics      - Run the Rust Parallel Forensic Scan"
	@echo "  make redo-env       - Recreate .env from .env.example"

build:
	$(DOCKER_COMPOSE) build

up:
	$(DOCKER_COMPOSE) up -d

down:
	$(DOCKER_COMPOSE) down

logs:
	$(DOCKER_COMPOSE) logs -f

test:
	$(PIP) install -r requirements.txt
	$(PYTEST) tests/

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type d -name ".pytest_cache" -exec rm -rf {} +
	rm -f forensics/*.log

forensics:
	cd $(RUST_TOOL) && cargo run

redo-env:
	cp .env.example .env
	@echo ".env file has been recreated from .env.example"
