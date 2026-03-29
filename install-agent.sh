#!/bin/bash
# certctl Agent Install Script
# Detects OS (Linux/macOS) and architecture, downloads binary from GitHub Releases,
# installs to system path, configures service (systemd/launchd), and prompts for config.

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
GITHUB_REPO="shankar0123/certctl"
RELEASE_URL="https://github.com/${GITHUB_REPO}/releases/latest/download"
INSTALL_DIR="/usr/local/bin"
SERVICE_NAME="certctl-agent"

# Detect OS and architecture
detect_platform() {
    local os="$(uname -s)"
    local arch="$(uname -m)"

    case "$os" in
        Linux*)
            OS_TYPE="linux"
            ;;
        Darwin*)
            OS_TYPE="darwin"
            ;;
        *)
            echo -e "${RED}Error: Unsupported OS: $os${NC}"
            exit 1
            ;;
    esac

    case "$arch" in
        x86_64)
            ARCH_TYPE="amd64"
            ;;
        aarch64|arm64)
            ARCH_TYPE="arm64"
            ;;
        *)
            echo -e "${RED}Error: Unsupported architecture: $arch${NC}"
            exit 1
            ;;
    esac
}

# Print usage information
usage() {
    cat <<EOF
Usage: $0 [OPTIONS]

Install and configure the certctl agent on your system.

OPTIONS:
    -h, --help          Show this help message
    --server-url URL    Set CERTCTL_SERVER_URL (skips interactive prompt)
    --api-key KEY       Set CERTCTL_API_KEY (skips interactive prompt)
    --no-start          Install but don't start the service

EOF
}

# Parse command-line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                usage
                exit 0
                ;;
            --server-url)
                SERVER_URL="$2"
                shift 2
                ;;
            --api-key)
                API_KEY="$2"
                shift 2
                ;;
            --no-start)
                NO_START=true
                shift
                ;;
            *)
                echo -e "${RED}Error: Unknown option: $1${NC}"
                usage
                exit 1
                ;;
        esac
    done
}

# Check if running as root/sudo on Linux
check_privileges() {
    if [[ "$OS_TYPE" == "linux" && "$EUID" -ne 0 ]]; then
        echo -e "${RED}Error: This script must be run as root on Linux. Try: sudo $0${NC}"
        exit 1
    fi
}

# Download agent binary from GitHub Releases
download_binary() {
    local binary_name="certctl-agent-${OS_TYPE}-${ARCH_TYPE}"
    local download_url="${RELEASE_URL}/${binary_name}"

    echo -e "${YELLOW}Downloading certctl agent (${OS_TYPE}-${ARCH_TYPE})...${NC}"

    if ! command -v curl &> /dev/null; then
        echo -e "${RED}Error: curl is required but not installed${NC}"
        exit 1
    fi

    local temp_file=$(mktemp)
    trap "rm -f $temp_file" EXIT

    if ! curl -sSL -f "$download_url" -o "$temp_file"; then
        echo -e "${RED}Error: Failed to download binary from $download_url${NC}"
        echo "Make sure the latest release exists on GitHub with the binary asset for ${OS_TYPE}-${ARCH_TYPE}."
        exit 1
    fi

    chmod +x "$temp_file"
    echo "$temp_file"
}

# Install binary to system path
install_binary() {
    local binary_path="$1"

    echo -e "${YELLOW}Installing to $INSTALL_DIR/$SERVICE_NAME...${NC}"

    if [[ "$OS_TYPE" == "linux" ]]; then
        cp "$binary_path" "$INSTALL_DIR/$SERVICE_NAME"
    else
        # macOS: use sudo if not already running as root
        if [[ "$EUID" -ne 0 ]]; then
            sudo cp "$binary_path" "$INSTALL_DIR/$SERVICE_NAME"
        else
            cp "$binary_path" "$INSTALL_DIR/$SERVICE_NAME"
        fi
    fi

    chmod +x "$INSTALL_DIR/$SERVICE_NAME"
    echo -e "${GREEN}Binary installed: $INSTALL_DIR/$SERVICE_NAME${NC}"
}

# Prompt for configuration (unless --server-url and --api-key provided)
prompt_for_config() {
    if [[ -z "${SERVER_URL:-}" ]]; then
        echo ""
        echo -e "${YELLOW}Enter certctl server URL (e.g., https://certctl.example.com):${NC}"
        read -r SERVER_URL
        if [[ -z "$SERVER_URL" ]]; then
            echo -e "${RED}Error: Server URL is required${NC}"
            exit 1
        fi
    fi

    if [[ -z "${API_KEY:-}" ]]; then
        echo -e "${YELLOW}Enter certctl API key:${NC}"
        read -sr API_KEY
        echo ""
        if [[ -z "$API_KEY" ]]; then
            echo -e "${RED}Error: API key is required${NC}"
            exit 1
        fi
    fi

    if [[ -z "${AGENT_ID:-}" ]]; then
        local default_agent_id="$(hostname)"
        echo -e "${YELLOW}Enter agent ID (default: $default_agent_id):${NC}"
        read -r AGENT_ID
        if [[ -z "$AGENT_ID" ]]; then
            AGENT_ID="$default_agent_id"
        fi
    fi
}

# Create configuration directory and env file (Linux)
setup_linux_config() {
    local config_dir="/etc/certctl"
    local config_file="$config_dir/agent.env"
    local key_dir="/var/lib/certctl/keys"

    echo -e "${YELLOW}Creating configuration directory...${NC}"

    # Create /etc/certctl with restrictive permissions
    mkdir -p "$config_dir"
    chmod 755 "$config_dir"

    # Create key storage directory with 0700 permissions
    mkdir -p "$key_dir"
    chmod 700 "$key_dir"

    # Write agent configuration (overwrite if exists)
    cat > "$config_file" <<EOF
# certctl Agent Configuration
# Generated by install-agent.sh on $(date)

# Agent ID (unique identifier in the fleet)
CERTCTL_AGENT_ID=$AGENT_ID

# Control plane server URL
CERTCTL_SERVER_URL=$SERVER_URL

# API authentication key
CERTCTL_API_KEY=$API_KEY

# Key generation mode (agent = agent-side keygen, server = server-side for demo only)
CERTCTL_KEYGEN_MODE=agent

# Key storage directory (agent-side keygen)
CERTCTL_KEY_DIR=$key_dir

# Logging level (debug, info, warn, error)
# CERTCTL_LOG_LEVEL=info

# Discovery directories (comma-separated paths to scan for existing certs)
# CERTCTL_DISCOVERY_DIRS=/etc/letsencrypt/live,/etc/ssl/certs

# Enable deployment verification (TLS endpoint check post-deployment)
# CERTCTL_VERIFY_DEPLOYMENT=true
EOF

    # Restrict permissions on env file (contains API key)
    chmod 600 "$config_file"
    echo -e "${GREEN}Configuration written to: $config_file${NC}"
}

# Create configuration directory and env file (macOS)
setup_macos_config() {
    local config_dir="$HOME/.certctl"
    local config_file="$config_dir/agent.env"
    local key_dir="$config_dir/keys"

    echo -e "${YELLOW}Creating configuration directory...${NC}"

    # Create ~/.certctl with restrictive permissions
    mkdir -p "$config_dir"
    chmod 700 "$config_dir"

    # Create key storage directory
    mkdir -p "$key_dir"
    chmod 700 "$key_dir"

    # Write agent configuration (overwrite if exists)
    cat > "$config_file" <<EOF
# certctl Agent Configuration
# Generated by install-agent.sh on $(date)

# Agent ID (unique identifier in the fleet)
CERTCTL_AGENT_ID=$AGENT_ID

# Control plane server URL
CERTCTL_SERVER_URL=$SERVER_URL

# API authentication key
CERTCTL_API_KEY=$API_KEY

# Key generation mode (agent = agent-side keygen, server = server-side for demo only)
CERTCTL_KEYGEN_MODE=agent

# Key storage directory (agent-side keygen)
CERTCTL_KEY_DIR=$key_dir

# Logging level (debug, info, warn, error)
# CERTCTL_LOG_LEVEL=info

# Discovery directories (comma-separated paths to scan for existing certs)
# CERTCTL_DISCOVERY_DIRS=/etc/letsencrypt/live,/etc/ssl/certs

# Enable deployment verification (TLS endpoint check post-deployment)
# CERTCTL_VERIFY_DEPLOYMENT=true
EOF

    # Restrict permissions on env file (contains API key)
    chmod 600 "$config_file"
    echo -e "${GREEN}Configuration written to: $config_file${NC}"
}

# Create and enable systemd service (Linux only)
setup_systemd_service() {
    local service_file="/etc/systemd/system/${SERVICE_NAME}.service"

    echo -e "${YELLOW}Creating systemd service file...${NC}"

    cat > "$service_file" <<'EOF'
[Unit]
Description=certctl Agent - Certificate Lifecycle Management
Documentation=https://github.com/shankar0123/certctl
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Restart=on-failure
RestartSec=10s
StandardOutput=journal
StandardError=journal

# Load environment from /etc/certctl/agent.env
EnvironmentFile=/etc/certctl/agent.env

# Command to start the agent
ExecStart=/usr/local/bin/certctl-agent

[Install]
WantedBy=multi-user.target
EOF

    chmod 644 "$service_file"
    echo -e "${GREEN}Service file created: $service_file${NC}"

    # Reload systemd daemon
    systemctl daemon-reload
}

# Create and enable launchd plist (macOS only)
setup_launchd_service() {
    local plist_file="$HOME/Library/LaunchAgents/com.certctl.agent.plist"
    local config_file="$HOME/.certctl/agent.env"
    local launcher_script="$HOME/.certctl/launcher.sh"
    local home_dir="$HOME"

    echo -e "${YELLOW}Creating launchd service file...${NC}"

    mkdir -p "$(dirname "$plist_file")"

    # Create wrapper script that sources env file before executing agent
    cat > "$launcher_script" <<'LAUNCHER_SCRIPT'
#!/bin/bash
set -a
source "$HOME/.certctl/agent.env"
set +a
exec /usr/local/bin/certctl-agent
LAUNCHER_SCRIPT

    chmod 755 "$launcher_script"

    # Create plist that references the launcher script
    cat > "$plist_file" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.certctl.agent</string>
    <key>ProgramArguments</key>
    <array>
        <string>$home_dir/.certctl/launcher.sh</string>
    </array>
    <key>EnvironmentVariables</key>
    <dict>
        <key>PATH</key>
        <string>/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
        <key>HOME</key>
        <string>$home_dir</string>
    </dict>
    <key>KeepAlive</key>
    <true/>
    <key>RunAtLoad</key>
    <true/>
    <key>StandardErrorPath</key>
    <string>$home_dir/.certctl/agent.log</string>
    <key>StandardOutPath</key>
    <string>$home_dir/.certctl/agent.log</string>
</dict>
</plist>
EOF

    chmod 644 "$plist_file"
    echo -e "${GREEN}Service file created: $plist_file${NC}"
    echo -e "${GREEN}Launcher script created: $launcher_script${NC}"
}

# Start the agent service
start_service() {
    if [[ "${NO_START:-false}" == "true" ]]; then
        echo -e "${YELLOW}Service not started (--no-start flag used)${NC}"
        return
    fi

    echo -e "${YELLOW}Starting certctl agent service...${NC}"

    if [[ "$OS_TYPE" == "linux" ]]; then
        systemctl enable "$SERVICE_NAME"
        systemctl start "$SERVICE_NAME"
        sleep 2
        if systemctl is-active --quiet "$SERVICE_NAME"; then
            echo -e "${GREEN}Service started successfully${NC}"
        else
            echo -e "${RED}Warning: Service may not have started. Check logs with: systemctl status $SERVICE_NAME${NC}"
        fi
    else
        # macOS: load launchd service for current user
        launchctl load "$HOME/Library/LaunchAgents/com.certctl.agent.plist" 2>/dev/null || true
        sleep 1
        echo -e "${GREEN}Service loaded into launchd${NC}"
    fi
}

# Print success message with next steps
print_summary() {
    echo ""
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}certctl Agent Installation Complete${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo ""
    echo "Configuration:"
    if [[ "$OS_TYPE" == "linux" ]]; then
        echo "  Config file:    /etc/certctl/agent.env"
        echo "  Key storage:    /var/lib/certctl/keys"
        echo "  Service:        /etc/systemd/system/${SERVICE_NAME}.service"
        echo "  View logs:      journalctl -u ${SERVICE_NAME} -f"
    else
        echo "  Config file:    $HOME/.certctl/agent.env"
        echo "  Key storage:    $HOME/.certctl/keys"
        echo "  Service:        $HOME/Library/LaunchAgents/com.certctl.agent.plist"
        echo "  View logs:      tail -f $HOME/.certctl/agent.log"
    fi
    echo ""
    echo "Next steps:"
    echo "  1. Verify the service is running"
    if [[ "$OS_TYPE" == "linux" ]]; then
        echo "     systemctl status ${SERVICE_NAME}"
    else
        echo "     launchctl list | grep certctl"
    fi
    echo ""
    echo "  2. Visit your certctl dashboard: $SERVER_URL"
    echo "  3. The agent should appear in the fleet overview within 30 seconds"
    echo ""
}

# Main installation flow
main() {
    parse_args "$@"
    detect_platform
    check_privileges

    echo -e "${GREEN}certctl Agent Installer${NC}"
    echo "Detected platform: ${OS_TYPE}-${ARCH_TYPE}"
    echo ""

    prompt_for_config

    # Download and install binary
    local binary_path
    binary_path=$(download_binary)
    install_binary "$binary_path"

    # Setup OS-specific configuration
    if [[ "$OS_TYPE" == "linux" ]]; then
        setup_linux_config
        setup_systemd_service
    else
        setup_macos_config
        setup_launchd_service
    fi

    # Start the service
    start_service

    # Print summary
    print_summary
}

main "$@"
