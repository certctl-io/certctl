.PHONY: help build run test lint verify clean docker-up docker-down migrate-up migrate-down generate test-cover frontend-build qa-stats

# Default target - show help
help:
	@echo "Certctl Development Commands"
	@echo "============================="
	@echo ""
	@echo "Build & Run:"
	@echo "  make build          Build server and agent binaries"
	@echo "  make run            Run server locally (requires DB)"
	@echo "  make run-agent      Run agent locally"
	@echo ""
	@echo "Testing & Quality:"
	@echo "  make test           Run all tests"
	@echo "  make test-verbose   Run tests with verbose output"
	@echo "  make lint           Run linter (golangci-lint)"
	@echo "  make fmt            Format code with gofmt"
	@echo "  make verify         Pre-commit gate: fmt + vet + lint + test (CI-parity)"
	@echo ""
	@echo "Database:"
	@echo "  make migrate-up     Run migrations (requires DB_URL)"
	@echo "  make migrate-down   Rollback last migration"
	@echo "  make db-seed        Seed database with test data"
	@echo ""
	@echo "Docker:"
	@echo "  make docker-build   Build Docker images"
	@echo "  make docker-up      Start Docker Compose stack"
	@echo "  make docker-down    Stop Docker Compose stack"
	@echo "  make docker-logs    View Docker logs"
	@echo "  make docker-clean   Remove Docker resources"
	@echo ""
	@echo "Code Generation:"
	@echo "  make generate       Run go generate"
	@echo "  make clean          Clean build artifacts"
	@echo ""

# Build targets
build:
	@echo "Building server and agent..."
	mkdir -p bin
	CGO_ENABLED=0 go build -o bin/server ./cmd/server
	CGO_ENABLED=0 go build -o bin/agent ./cmd/agent
	@echo "Build complete: bin/server, bin/agent"

build-server:
	@echo "Building server..."
	mkdir -p bin
	CGO_ENABLED=0 go build -o bin/server ./cmd/server
	@echo "Server build complete"

build-agent:
	@echo "Building agent..."
	mkdir -p bin
	CGO_ENABLED=0 go build -o bin/agent ./cmd/agent
	@echo "Agent build complete"

# Run targets
run: build-server
	@echo "Starting server (requires DATABASE_URL or DB_* env vars)..."
	./bin/server

run-agent: build-agent
	@echo "Starting agent (requires SERVER_URL and API_KEY env vars)..."
	./bin/agent

# Testing targets
test:
	@echo "Running tests..."
	go test ./...

test-verbose:
	@echo "Running tests with verbose output..."
	go test -v ./...

test-coverage:
	@echo "Running tests with coverage..."
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

test-cover:
	@echo "Running tests with coverage..."
	go test ./internal/service/... ./internal/api/handler/... ./internal/integration/... -count=1 -cover -coverprofile=coverage.out
	@echo "Coverage report: coverage.out"

# Linting targets
lint:
	@echo "Running golangci-lint..."
	@which golangci-lint > /dev/null || (echo "Installing golangci-lint..." && go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest)
	golangci-lint run ./...

fmt:
	@echo "Formatting code..."
	go fmt ./...
	@echo "Code formatted"

vet:
	@echo "Running go vet..."
	go vet ./...

# verify: aggregate pre-commit gate. Mirrors what CI enforces, so
# running `make verify` locally before committing prevents the
# class of breakages that ship green-locally / red-on-CI (e.g.
# Bundle-9's ST1018 invisible-Unicode-literal hits, which `go vet`
# alone cannot catch — staticcheck under golangci-lint does).
verify:
	@echo "==> fmt"
	@go fmt ./... | { ! grep -q '.'; } || (echo "gofmt produced changes — commit them" && exit 1)
	@echo "==> go vet ./..."
	@go vet ./...
	@echo "==> golangci-lint run ./... (incl. staticcheck ST*)"
	@which golangci-lint > /dev/null || (echo "Installing golangci-lint..." && go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest)
	@golangci-lint run ./... --timeout 5m
	@echo "==> go test -short ./..."
	@go test -short -count=1 ./...
	@echo ""
	@echo "verify: PASS — safe to commit"

# Database targets (requires migrate tool)
migrate-up:
	@echo "Running migrations..."
	@which migrate > /dev/null || (echo "Installing migrate CLI..." && go install -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate@latest)
	migrate -path migrations -database "${DB_URL:-postgres://certctl:certctl@localhost:5432/certctl?sslmode=disable}" up

migrate-down:
	@echo "Rolling back last migration..."
	@which migrate > /dev/null || (echo "Installing migrate CLI..." && go install -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate@latest)
	migrate -path migrations -database "${DB_URL:-postgres://certctl:certctl@localhost:5432/certctl?sslmode=disable}" down 1

migrate-status:
	@echo "Checking migration status..."
	@which migrate > /dev/null || (echo "Installing migrate CLI..." && go install -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate@latest)
	migrate -path migrations -database "${DB_URL:-postgres://certctl:certctl@localhost:5432/certctl?sslmode=disable}" version

db-seed:
	@echo "Seeding database with test data..."
	go run ./scripts/seed/main.go

# Docker targets
docker-build:
	@echo "Building Docker images..."
	docker-compose -f deploy/docker-compose.yml build

docker-up:
	@echo "Starting Docker Compose stack..."
	docker-compose -f deploy/docker-compose.yml up -d
	@echo "Stack running. Access server at http://localhost:8443"

docker-up-dev:
	@echo "Starting Docker Compose stack (dev mode)..."
	docker-compose -f deploy/docker-compose.yml -f deploy/docker-compose.dev.yml up -d
	@echo "Stack running. PgAdmin at http://localhost:5050"

docker-down:
	@echo "Stopping Docker Compose stack..."
	docker-compose -f deploy/docker-compose.yml down

docker-logs:
	docker-compose -f deploy/docker-compose.yml logs -f

docker-logs-server:
	docker-compose -f deploy/docker-compose.yml logs -f certctl-server

docker-logs-agent:
	docker-compose -f deploy/docker-compose.yml logs -f certctl-agent

docker-clean:
	@echo "Removing Docker resources..."
	docker-compose -f deploy/docker-compose.yml down -v
	@echo "Cleaned up"

# Code generation
generate:
	@echo "Running go generate..."
	go generate ./...
	@echo "Code generation complete"

# Frontend build
frontend-build:
	@echo "Building frontend..."
	cd web && npm ci && npx vite build
	@echo "Frontend build complete"

# QA Suite Stats — Bundle P / Strengthening #8.
# Single source-of-truth for every count claim in docs/qa-test-guide.md +
# docs/testing-guide.md. The Strengthening #6 CI drift guards consume the
# same numbers, eliminating the doc-drift class structurally.
qa-stats:
	@echo "=== certctl QA Suite Stats ==="
	@echo "Date: $$(date +%Y-%m-%d)"
	@echo "HEAD: $$(git rev-parse HEAD 2>/dev/null || echo 'not-a-git-repo')"
	@echo ""
	@echo "Backend test files: $$(find . -name '*_test.go' -not -path './web/*' 2>/dev/null | wc -l | tr -d ' ')"
	@echo "Backend Test functions: $$(find . -name '*_test.go' -not -path './web/*' 2>/dev/null | xargs grep -c '^func Test' 2>/dev/null | awk -F: '{s+=$$2} END{print s+0}')"
	@echo "Backend t.Run subtests: $$(find . -name '*_test.go' -not -path './web/*' 2>/dev/null | xargs grep -c 't\.Run(' 2>/dev/null | awk -F: '{s+=$$2} END{print s+0}')"
	@echo "Frontend test files: $$(find web/src -name '*.test.ts' -o -name '*.test.tsx' 2>/dev/null | wc -l | tr -d ' ')"
	@echo "Fuzz targets: $$(grep -rE 'func Fuzz[A-Z]' --include='*_test.go' . 2>/dev/null | wc -l | tr -d ' ')"
	@echo "t.Skip sites: $$(grep -rE 't\.Skip(Now|f)?\(' --include='*_test.go' . 2>/dev/null | wc -l | tr -d ' ')"
	@echo "qa_test.go Part_ subtests: $$(grep -cE 't\.Run\(\"Part[0-9]+_' deploy/test/qa_test.go 2>/dev/null || echo 0)"
	@echo "testing-guide.md Parts: $$(grep -cE '^## Part [0-9]+:' docs/testing-guide.md 2>/dev/null || echo 0)"
	@echo "Seed unique mc-* IDs:  $$(grep -oE "mc-[a-z0-9_-]+" migrations/seed_demo.sql 2>/dev/null | sort -u | wc -l | tr -d ' ')"
	@echo "Seed unique ag-* IDs:  $$(grep -oE "ag-[a-z0-9_-]+" migrations/seed_demo.sql 2>/dev/null | sort -u | wc -l | tr -d ' ') (incl. agent_groups; agents-table count is 12)"
	@echo "Seed unique iss-* IDs: $$(grep -oE "iss-[a-z0-9_-]+" migrations/seed_demo.sql 2>/dev/null | sort -u | wc -l | tr -d ' ') (issuers table count is 13)"
	@echo "Seed unique tgt-* IDs: $$(grep -oE "tgt-[a-z0-9_-]+" migrations/seed_demo.sql 2>/dev/null | sort -u | wc -l | tr -d ' ')"
	@echo "Seed unique nst-* IDs: $$(grep -oE "nst-[a-z0-9_-]+" migrations/seed_demo.sql 2>/dev/null | sort -u | wc -l | tr -d ' ')"

# Cleanup
clean:
	@echo "Cleaning build artifacts..."
	rm -rf bin/ dist/ coverage.out coverage.html
	go clean -testcache
	cd web && rm -rf node_modules dist
	@echo "Cleanup complete"

install-tools:
	@echo "Installing development tools..."
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate@latest
	go install github.com/cosmtrek/air@latest
	@echo "Tools installed"
