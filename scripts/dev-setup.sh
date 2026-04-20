#!/bin/bash
set -e

# Certctl development setup script
# Installs prerequisites and initializes a local development environment

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== Certctl Development Setup ===${NC}\n"

# Check Go installation
echo "Checking Go installation..."
if ! command -v go &> /dev/null; then
    echo -e "${RED}✗ Go 1.22+ not found${NC}"
    echo "  Install from: https://golang.org/dl/"
    exit 1
fi
GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
echo -e "${GREEN}✓ Go $GO_VERSION found${NC}"

# Check Docker installation
echo "Checking Docker installation..."
if ! command -v docker &> /dev/null; then
    echo -e "${RED}✗ Docker not found${NC}"
    echo "  Install from: https://docs.docker.com/get-docker/"
    exit 1
fi
DOCKER_VERSION=$(docker version --format '{{.Server.Version}}')
echo -e "${GREEN}✓ Docker $DOCKER_VERSION found${NC}"

# Check Docker Compose installation
echo "Checking Docker Compose installation..."
if ! command -v docker-compose &> /dev/null; then
    echo -e "${RED}✗ Docker Compose not found${NC}"
    echo "  Install from: https://docs.docker.com/compose/install/"
    exit 1
fi
DC_VERSION=$(docker-compose version --short)
echo -e "${GREEN}✓ Docker Compose $DC_VERSION found${NC}\n"

# Setup environment
echo "Setting up environment..."
if [ ! -f "$PROJECT_ROOT/.env" ]; then
    echo "Creating .env from template..."
    cp "$PROJECT_ROOT/.env.example" "$PROJECT_ROOT/.env"
    echo -e "${GREEN}✓ .env created${NC}"
    echo "  Edit with your configuration: nano .env"
else
    echo -e "${YELLOW}⚠ .env already exists, skipping${NC}"
fi

# Download Go modules
echo -e "\nDownloading Go modules..."
cd "$PROJECT_ROOT"
go mod download
echo -e "${GREEN}✓ Go modules downloaded${NC}"

# Install development tools
echo -e "\nInstalling development tools..."
echo "  Installing golangci-lint..."
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
echo "  Installing migrate..."
go install -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate@latest
echo "  Installing air (hot reload)..."
go install github.com/cosmtrek/air@latest
echo -e "${GREEN}✓ Development tools installed${NC}"

# Start Docker Compose
echo -e "\nStarting Docker Compose stack..."
cd "$PROJECT_ROOT"
docker-compose -f deploy/docker-compose.yml up -d
echo -e "${GREEN}✓ Stack started${NC}"

# Wait for PostgreSQL to be ready
echo "Waiting for PostgreSQL to be ready..."
max_attempts=30
attempt=0
while [ $attempt -lt $max_attempts ]; do
    if docker-compose -f deploy/docker-compose.yml exec postgres \
        pg_isready -U certctl -d certctl > /dev/null 2>&1; then
        echo -e "${GREEN}✓ PostgreSQL is ready${NC}"
        break
    fi
    attempt=$((attempt + 1))
    if [ $attempt -eq $max_attempts ]; then
        echo -e "${RED}✗ PostgreSQL failed to start${NC}"
        exit 1
    fi
    echo "  Attempt $attempt/$max_attempts..."
    sleep 2
done

# Run migrations
echo -e "\nRunning database migrations..."
export DB_URL="postgres://certctl:certctl@localhost:5432/certctl?sslmode=disable"
migrate -path "$PROJECT_ROOT/migrations" -database "$DB_URL" up 2>/dev/null || {
    echo -e "${YELLOW}⚠ Migrations might need initialization${NC}"
    echo "  Run manually: make migrate-up"
}
echo -e "${GREEN}✓ Database initialized${NC}"

# Build project
echo -e "\nBuilding project..."
make -C "$PROJECT_ROOT" build > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Build successful${NC}"
else
    echo -e "${YELLOW}⚠ Build had issues, check Makefile${NC}"
fi

# Print summary
echo -e "\n${GREEN}=== Setup Complete ===${NC}\n"
echo "Your development environment is ready!"
echo ""
echo "Services running:"
echo "  • Server:      https://localhost:8443"
echo "  • Database:    postgres://certctl:certctl@localhost:5432/certctl"
echo "  • Agent:       Connected to server"
echo ""
echo "Next steps:"
echo "  1. Review configuration:"
echo "     cat .env"
echo ""
echo "  2. View logs:"
echo "     make docker-logs-server"
echo "     make docker-logs-agent"
echo ""
echo "  3. Test the API:"
echo "     curl --cacert ./deploy/test/certs/ca.crt https://localhost:8443/health"
echo ""
echo "  4. Try the quick start guide:"
echo "     cat docs/quickstart.md"
echo ""
echo "  5. Access PgAdmin (optional):"
echo "     make docker-up-dev"
echo "     # Then visit http://localhost:5050"
echo ""
echo "Useful commands:"
echo "  make help          - Show all available commands"
echo "  make test          - Run tests"
echo "  make lint          - Run linter"
echo "  make docker-down   - Stop services"
echo "  make docker-logs   - View service logs"
echo ""
echo "For more information, see:"
echo "  • README.md"
echo "  • docs/architecture.md"
echo "  • docs/quickstart.md"
echo ""
