#!/bin/bash
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() { echo -e "${BLUE}ℹ️  $1${NC}"; }
log_success() { echo -e "${GREEN}✅ $1${NC}"; }
log_warning() { echo -e "${YELLOW}⚠️  $1${NC}"; }
log_error() { echo -e "${RED}❌ $1${NC}"; }

# Error handler
handle_error() {
    log_error "Installation failed at line $1"
    log_error "Check the error above and try again"
    log_error "For help, visit: https://github.com/your-repo/issues"
    exit 1
}

trap 'handle_error $LINENO' ERR

echo "🔐 KeyVault Installation Script"
echo "================================"

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   log_error "This script should not be run as root for security reasons"
   exit 1
fi

# Check dependencies
log_info "Checking dependencies..."

if ! command -v docker &> /dev/null; then
    log_error "Docker is required but not installed"
    log_info "Install Docker: https://docs.docker.com/get-docker/"
    exit 1
fi

# Check Docker daemon
if ! docker info &> /dev/null; then
    log_error "Docker daemon is not running"
    log_info "Start Docker and try again"
    exit 1
fi

# Check Docker Compose
if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
    log_error "Docker Compose is required but not installed"
    log_info "Install Docker Compose: https://docs.docker.com/compose/install/"
    exit 1
fi

# Check if ports are available
if lsof -Pi :8080 -sTCP:LISTEN -t >/dev/null 2>&1; then
    log_error "Port 8080 is already in use"
    log_info "Stop the service using port 8080 or change the port in docker-compose.yml"
    exit 1
fi

log_success "All dependencies are available"

# Generate master key if it doesn't exist
if [ ! -f "config/master.key" ]; then
    log_info "Generating master encryption key..."
    mkdir -p config
    
    # Check if openssl is available
    if ! command -v openssl &> /dev/null; then
        log_error "OpenSSL is required to generate encryption keys"
        exit 1
    fi
    
    openssl rand -hex 16 > config/master.key
    chmod 600 config/master.key
    log_success "Master key generated and secured"
else
    log_info "Using existing master key"
fi

# Create minimal config if it doesn't exist
if [ ! -f "config/agent-minimal.yaml" ]; then
    log_info "Creating minimal configuration..."
    cat > config/agent-minimal.yaml << 'EOF'
server:
  host: "0.0.0.0"
  port: 8080

database:
  type: sqlite
  path: /app/data/vault.db

control_plane:
  enabled: false

security:
  master_key_file: /app/config/master.key

logging:
  level: info
EOF
    log_success "Configuration created"
else
    log_info "Using existing configuration"
fi

# Create data directory
mkdir -p data
chmod 755 data

# Start services
log_info "Starting KeyVault services..."
log_info "This may take a few minutes on first run..."

# Clean up any existing containers
docker compose down --remove-orphans 2>/dev/null || true

# Build and start
if ! docker compose up -d --build; then
    log_error "Failed to start services"
    log_info "Check logs with: docker compose logs"
    exit 1
fi

# Wait for services to be ready with timeout
log_info "Waiting for services to start..."
TIMEOUT=60
COUNTER=0

while [ $COUNTER -lt $TIMEOUT ]; do
    if curl -s http://localhost:8080/api/v1/system/stats > /dev/null 2>&1; then
        break
    fi
    sleep 2
    COUNTER=$((COUNTER + 2))
    echo -n "."
done

echo ""

# Check if vault is running
if curl -s http://localhost:8080/api/v1/system/stats > /dev/null 2>&1; then
    log_success "KeyVault is running successfully!"
    echo ""
    echo "🌐 Web Interface: http://localhost:8080"
    echo "📚 API Documentation: http://localhost:8080/swagger/index.html"
    echo "🔑 Demo Login: admin / admin123"
    echo ""
    echo "📖 Next steps:"
    echo "  1. Visit the web interface to manage secrets"
    echo "  2. Build CLI: cd vault-agent && go build -o vault-cli cmd/cli/main.go"
    echo "  3. Configure CLI: echo 'endpoint: http://localhost:8080' > .vault-cli.yaml"
    echo "  4. Test CLI: ./vault-agent/vault-cli system status"
    echo ""
    echo "📋 Useful commands:"
    echo "  - View logs: docker compose logs -f"
    echo "  - Stop services: docker compose down"
    echo "  - Restart services: docker compose restart"
else
    log_error "KeyVault failed to start within ${TIMEOUT} seconds"
    log_info "Check logs with: docker compose logs vault-agent"
    log_info "Common issues:"
    echo "  - Port 8080 already in use"
    echo "  - Insufficient disk space"
    echo "  - Docker daemon issues"
    exit 1
fi
