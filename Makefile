# ===========================================================================
# AgentOps Security Mesh — Makefile
# Usage: make <target>
# ===========================================================================

.PHONY: help install dev test attack-demo load-test deploy clean lint fmt

# Default target
help:
	@echo ""
	@echo "  AgentOps Security Mesh"
	@echo "  ─────────────────────────────────────────"
	@echo "  make install       Install all dependencies"
	@echo "  make dev           Start full stack locally (infra + backend + frontend)"
	@echo "  make test          Run integration test suite"
	@echo "  make attack-demo   Run the scripted hackathon demo"
	@echo "  make load-test     Run concurrent stress test"
	@echo "  make lint          Lint Python and TypeScript"
	@echo "  make fmt           Auto-format all code"
	@echo "  make deploy        Deploy to Azure Container Apps via Bicep"
	@echo "  make clean         Stop all Docker containers and remove volumes"
	@echo ""

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

install:
	@echo "→ Installing backend dependencies..."
	cd backend && pip install -r requirements.txt
	@echo "→ Installing frontend dependencies..."
	cd frontend && npm install
	@echo "→ Copying .env.example to .env (if not present)..."
	@test -f .env || cp .env.example .env
	@echo "✓ Done. Edit .env before starting the stack."

# ---------------------------------------------------------------------------
# Local Development
# ---------------------------------------------------------------------------

dev: _infra-up
	@echo "→ Starting backend and frontend..."
	@trap 'kill 0' SIGINT; \
	  cd backend && uvicorn app.main:app --reload --host 0.0.0.0 --port 8000 & \
	  cd frontend && npm run dev & \
	  wait

_infra-up:
	@echo "→ Starting Redis and Neo4j..."
	docker-compose up -d redis neo4j
	@echo "→ Waiting for Redis..."
	@until docker-compose exec redis redis-cli ping 2>/dev/null | grep -q PONG; do sleep 1; done
	@echo "✓ Redis ready."
	@echo "→ Waiting for Neo4j (up to 60s)..."
	@for i in $$(seq 1 12); do \
	  docker-compose exec neo4j cypher-shell -u neo4j -p "$${NEO4J_PASSWORD:-changeme_strong_password}" "RETURN 1" 2>/dev/null && break || sleep 5; \
	done
	@echo "✓ Neo4j ready."

# Start the full dockerised stack (production-like)
stack-up:
	docker-compose up --build -d
	@echo "✓ Stack started."
	@echo "  Frontend  → http://localhost:5173"
	@echo "  Backend   → http://localhost:8000"
	@echo "  API Docs  → http://localhost:8000/docs"
	@echo "  Neo4j UI  → http://localhost:7474"

stack-down:
	docker-compose down

# ---------------------------------------------------------------------------
# Testing
# ---------------------------------------------------------------------------

test: _infra-up
	@echo "→ Running integration tests..."
	cd backend && python -m pytest tests/test_integration.py -v --asyncio-mode=auto

test-unit:
	cd backend && python -m pytest tests/ -v --asyncio-mode=auto -k "not integration"

# ---------------------------------------------------------------------------
# Demo & Load Test
# ---------------------------------------------------------------------------

attack-demo:
	@echo "→ Running hackathon demo against http://localhost:8000 ..."
	python scripts/demo.py --backend-url http://localhost:8000

load-test:
	@echo "→ Running load test against http://localhost:8000 ..."
	python scripts/load_test.py --backend-url http://localhost:8000

# ---------------------------------------------------------------------------
# Code Quality
# ---------------------------------------------------------------------------

lint:
	@echo "→ Linting Python..."
	cd backend && ruff check app/ tests/
	@echo "→ Linting TypeScript..."
	cd frontend && npm run lint

fmt:
	@echo "→ Formatting Python..."
	cd backend && ruff format app/ tests/ && isort app/ tests/
	@echo "→ Formatting TypeScript..."
	cd frontend && npx prettier --write "src/**/*.{ts,tsx}"

# ---------------------------------------------------------------------------
# Azure Deployment
# ---------------------------------------------------------------------------

deploy:
	@echo "→ Deploying to Azure (resource group: $${AZURE_RESOURCE_GROUP:-agentops-rg})..."
	@test -n "$$AZURE_RESOURCE_GROUP" || (echo "ERROR: Set AZURE_RESOURCE_GROUP in .env" && exit 1)
	@test -n "$$AZURE_SUBSCRIPTION_ID" || (echo "ERROR: Set AZURE_SUBSCRIPTION_ID in .env" && exit 1)
	az group create \
	  --name $${AZURE_RESOURCE_GROUP} \
	  --location $${AZURE_LOCATION:-eastus}
	az deployment group create \
	  --resource-group $${AZURE_RESOURCE_GROUP} \
	  --template-file azure/main.bicep \
	  --parameters environmentName=$${AZURE_ENVIRONMENT_NAME:-agentops-prod}
	@echo "✓ Deployment complete."

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------

clean:
	@echo "→ Stopping all containers and removing volumes..."
	docker-compose down -v --remove-orphans
	@echo "✓ Clean."
