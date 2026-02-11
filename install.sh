#!/bin/sh
# Parachute Installer
# Usage: curl -fsSL https://raw.githubusercontent.com/parachute-security/parachute/main/install.sh | sh
# Options:
#   --demo    Start demo mode after installation (requires Docker)
#   --binary  Force binary installation (skip Docker)

set -e

REPO="parachute-security/parachute"
BINARY_NAME="parachute"
INSTALL_DIR="/usr/local/bin"
DEMO_MODE=false
FORCE_BINARY=false

# Parse arguments
for arg in "$@"; do
    case "$arg" in
        --demo) DEMO_MODE=true ;;
        --binary) FORCE_BINARY=true ;;
        --help|-h)
            echo "Parachute Installer"
            echo ""
            echo "Usage: install.sh [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --demo    Start demo mode after installation (requires Docker)"
            echo "  --binary  Force binary installation (skip Docker)"
            echo "  --help    Show this help message"
            exit 0
            ;;
    esac
done

# Detect OS and architecture
detect_platform() {
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    ARCH=$(uname -m)

    case "$ARCH" in
        x86_64|amd64) ARCH="amd64" ;;
        aarch64|arm64) ARCH="arm64" ;;
        *)
            echo "Error: Unsupported architecture: $ARCH"
            exit 1
            ;;
    esac

    case "$OS" in
        linux|darwin) ;;
        *)
            echo "Error: Unsupported OS: $OS"
            exit 1
            ;;
    esac

    echo "Detected platform: ${OS}/${ARCH}"
}

# Check if Docker is available
has_docker() {
    command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1
}

# Check if Docker Compose is available
has_compose() {
    docker compose version >/dev/null 2>&1
}

# Get latest release version from GitHub
get_latest_version() {
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | sed -E 's/.*"tag_name":\s*"([^"]+)".*/\1/'
    elif command -v wget >/dev/null 2>&1; then
        wget -qO- "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | sed -E 's/.*"tag_name":\s*"([^"]+)".*/\1/'
    else
        echo "Error: Neither curl nor wget found"
        exit 1
    fi
}

# Download binary from GitHub releases
install_binary() {
    VERSION=$(get_latest_version)
    if [ -z "$VERSION" ]; then
        echo "Error: Could not determine latest version"
        exit 1
    fi

    echo "Installing Parachute ${VERSION} for ${OS}/${ARCH}..."

    DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${VERSION}/${BINARY_NAME}-${OS}-${ARCH}"
    TMP_FILE=$(mktemp)

    if command -v curl >/dev/null 2>&1; then
        curl -fsSL -o "$TMP_FILE" "$DOWNLOAD_URL"
    else
        wget -qO "$TMP_FILE" "$DOWNLOAD_URL"
    fi

    chmod +x "$TMP_FILE"

    # Install to INSTALL_DIR (may need sudo)
    if [ -w "$INSTALL_DIR" ]; then
        mv "$TMP_FILE" "${INSTALL_DIR}/${BINARY_NAME}"
    else
        echo "Installing to ${INSTALL_DIR} (requires sudo)..."
        sudo mv "$TMP_FILE" "${INSTALL_DIR}/${BINARY_NAME}"
    fi

    echo "Parachute installed to ${INSTALL_DIR}/${BINARY_NAME}"
    "${INSTALL_DIR}/${BINARY_NAME}" --version
}

# Install via Docker
install_docker() {
    echo "Pulling Parachute Docker image..."
    docker pull parachutesecurity/parachute:latest
    echo "Docker image pulled: parachutesecurity/parachute:latest"
}

# Generate default config
generate_config() {
    CONFIG_DIR="${HOME}/.parachute"
    CONFIG_FILE="${CONFIG_DIR}/parachute.yaml"

    if [ -f "$CONFIG_FILE" ]; then
        echo "Config already exists at ${CONFIG_FILE}"
        return
    fi

    mkdir -p "$CONFIG_DIR"
    cat > "$CONFIG_FILE" << 'YAML'
auth:
  username: "admin"
  password_env: "PARACHUTE_PASSWORD"

risk_policy:
  block_commands:
    - "rm -rf /"
    - "rm -rf ~"
    - ":(){ :|:& };:"
    - "mkfs\\."
  require_approval:
    - "\\brm\\b"
    - "\\bsudo\\b"
    - "\\bgit\\b.*(push|force)"

egress:
  allow_domains:
    - "api.anthropic.com"
    - "api.openai.com"
    - "github.com"
    - "*.githubusercontent.com"
  pii_patterns:
    - "AKIA[0-9A-Z]{16}"
    - "-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----"

storage:
  type: "memory"

upstream: "http://localhost:3000"
listen: ":8080"
proxy_listen: ":8888"
YAML

    echo "Default config generated at ${CONFIG_FILE}"
}

# Run demo mode
run_demo() {
    if ! has_compose; then
        echo "Error: Docker Compose required for demo mode"
        exit 1
    fi

    echo ""
    echo "Starting Parachute demo..."
    echo "Dashboard will be available at: http://localhost:8080/dashboard/"
    echo "Username: admin | Password: demo"
    echo ""

    # Clone repo for demo compose file
    TMP_DIR=$(mktemp -d)
    if command -v git >/dev/null 2>&1; then
        git clone --depth 1 "https://github.com/${REPO}.git" "$TMP_DIR"
    else
        echo "Error: git is required for demo mode"
        exit 1
    fi

    cd "$TMP_DIR"
    docker compose -f docker-compose.demo.yml up --build
}

# Main
main() {
    echo ""
    echo "  Parachute - The Seatbelt for Your AI Agent"
    echo ""

    detect_platform

    if [ "$DEMO_MODE" = true ]; then
        if has_docker && has_compose; then
            run_demo
            exit 0
        else
            echo "Error: Docker and Docker Compose are required for demo mode"
            exit 1
        fi
    fi

    if [ "$FORCE_BINARY" = false ] && has_docker; then
        install_docker
        generate_config
        echo ""
        echo "Quick start:"
        echo "  docker run -p 8080:8080 -p 8888:8888 parachutesecurity/parachute:latest"
        echo ""
        echo "Demo mode:"
        echo "  curl -fsSL https://raw.githubusercontent.com/${REPO}/main/install.sh | sh -s -- --demo"
    else
        install_binary
        generate_config
        echo ""
        echo "Quick start:"
        echo "  export PARACHUTE_PASSWORD='your-password'"
        echo "  parachute --config ~/.parachute/parachute.yaml"
    fi

    echo ""
    echo "Documentation: https://github.com/${REPO}"
    echo ""
}

main
