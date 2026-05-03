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
GITHUB_REPO="certctl-io/certctl"
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
    --agent-id ID       Set CERTCTL_AGENT_ID (defaults to hostname)
    --no-start          Install but don't start the service

EXAMPLES:
    # Interactive install (download first):
    curl -sSLO https://raw.githubusercontent.com/${GITHUB_REPO}/master/install-agent.sh
    chmod +x install-agent.sh
    sudo ./install-agent.sh

    # Non-interactive install (pipe via curl):
    curl -sSL https://raw.githubusercontent.com/${GITHUB_REPO}/master/install-agent.sh \\
      | sudo bash -s -- \\
          --server-url https://certctl.example.com \\
          --api-key YOUR_API_KEY

CONTROL-PLANE TLS TRUST:
    The certctl server is HTTPS-only as of v2.2. This installer does NOT copy a CA
    bundle — the generated agent.env leaves TLS trust to the system root store by
    default. If the server uses a private/enterprise or self-signed CA, set
    CERTCTL_SERVER_CA_BUNDLE_PATH in the generated agent.env to point at the CA
    bundle, or (dev only) CERTCTL_SERVER_TLS_INSECURE_SKIP_VERIFY=true. See the
    commented block in the generated agent.env for the full menu.

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
                SERVER_URL="${2:-}"
                if [[ -z "$SERVER_URL" ]]; then
                    echo -e "${RED}Error: --server-url requires a value${NC}" >&2
                    exit 1
                fi
                shift 2
                ;;
            --server-url=*)
                SERVER_URL="${1#*=}"
                shift
                ;;
            --api-key)
                API_KEY="${2:-}"
                if [[ -z "$API_KEY" ]]; then
                    echo -e "${RED}Error: --api-key requires a value${NC}" >&2
                    exit 1
                fi
                shift 2
                ;;
            --api-key=*)
                API_KEY="${1#*=}"
                shift
                ;;
            --agent-id)
                AGENT_ID="${2:-}"
                if [[ -z "$AGENT_ID" ]]; then
                    echo -e "${RED}Error: --agent-id requires a value${NC}" >&2
                    exit 1
                fi
                shift 2
                ;;
            --agent-id=*)
                AGENT_ID="${1#*=}"
                shift
                ;;
            --no-start)
                NO_START=true
                shift
                ;;
            *)
                echo -e "${RED}Error: Unknown option: $1${NC}" >&2
                usage
                exit 1
                ;;
        esac
    done
}

# Ensure stdin is interactive before prompting. When the script is piped via
# curl|bash, stdin is the pipe from curl, so `read` hits EOF immediately and
# set -e aborts the script silently. Reopen stdin from the controlling terminal
# (/dev/tty) if available; otherwise print a helpful error pointing at the
# flag-based non-interactive install.
ensure_interactive_input() {
    # If all required config is already provided via flags, no prompting needed.
    if [[ -n "${SERVER_URL:-}" && -n "${API_KEY:-}" ]]; then
        return
    fi

    # Already interactive — nothing to do.
    if [[ -t 0 ]]; then
        return
    fi

    # Piped stdin — try to reopen from the controlling terminal. Actually
    # attempt to open /dev/tty inside a subshell: the device node may exist
    # even when the process has no controlling terminal (ENXIO on open), so
    # `[[ -r /dev/tty ]]` is not reliable.
    if ( exec </dev/tty ) 2>/dev/null; then
        exec </dev/tty
        return
    fi

    # No terminal available — emit clear guidance and exit.
    # Use printf '%b' so the ANSI color escapes in $RED/$NC are interpreted
    # rather than rendered as literal backslash sequences (a heredoc would
    # keep them as raw text).
    {
        printf '%b\n' "${RED}Error: No interactive terminal available.${NC}"
        printf '\n'
        printf 'The installer was piped through curl and no controlling terminal (/dev/tty)\n'
        printf 'is available for prompts. Pass the required values as flags instead:\n'
        printf '\n'
        printf '  curl -sSL https://raw.githubusercontent.com/%s/master/install-agent.sh \\\n' "$GITHUB_REPO"
        printf '    | sudo bash -s -- \\\n'
        printf '        --server-url https://certctl.example.com \\\n'
        printf '        --api-key YOUR_API_KEY\n'
        printf '\n'
        printf 'Or download the script first and run it directly:\n'
        printf '\n'
        printf '  curl -sSLO https://raw.githubusercontent.com/%s/master/install-agent.sh\n' "$GITHUB_REPO"
        printf '  chmod +x install-agent.sh\n'
        printf '  sudo ./install-agent.sh\n'
        printf '\n'
    } >&2
    exit 1
}

# Check if running as root/sudo on Linux
check_privileges() {
    if [[ "$OS_TYPE" == "linux" && "$EUID" -ne 0 ]]; then
        echo -e "${RED}Error: This script must be run as root on Linux. Try: sudo $0${NC}"
        exit 1
    fi
}

# Download agent binary from GitHub Releases
# IMPORTANT: main() captures this function's stdout via `binary_path=$(download_binary)`,
# so every status/error message MUST go to stderr (>&2). Only the final
# `echo "$temp_file"` is allowed on stdout — that's the return value.
#
# We deliberately do NOT register an EXIT trap to clean up $temp_file: because
# of the command substitution, this function runs in a subshell, and any EXIT
# trap set here fires when the subshell exits — which is *before* install_binary
# gets a chance to cp the file. Cleanup on success is install_binary's job
# (after the cp), and cleanup on curl failure is handled inline below.
download_binary() {
    local binary_name="certctl-agent-${OS_TYPE}-${ARCH_TYPE}"
    local download_url="${RELEASE_URL}/${binary_name}"

    echo -e "${YELLOW}Downloading certctl agent (${OS_TYPE}-${ARCH_TYPE})...${NC}" >&2

    if ! command -v curl &> /dev/null; then
        echo -e "${RED}Error: curl is required but not installed${NC}" >&2
        exit 1
    fi

    local temp_file
    temp_file=$(mktemp)

    if ! curl -sSL -f "$download_url" -o "$temp_file" >&2; then
        rm -f "$temp_file"
        echo -e "${RED}Error: Failed to download binary from $download_url${NC}" >&2
        echo "Make sure the latest release exists on GitHub with the binary asset for ${OS_TYPE}-${ARCH_TYPE}." >&2
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

    # Clean up the temp file created by download_binary. We can't use an EXIT
    # trap inside download_binary because it runs in a subshell (command
    # substitution), so the trap would fire before we got here. Doing it
    # explicitly after the successful cp is the simplest correct pattern.
    rm -f "$binary_path"
}

# Prompt for configuration. Any value supplied via flag is honored as-is
# and we only prompt for the missing pieces. `read || true` prevents set -e
# from aborting the script on EOF — instead the empty check below fires the
# proper "required" error message.
prompt_for_config() {
    if [[ -z "${SERVER_URL:-}" ]]; then
        echo ""
        echo -e "${YELLOW}Enter certctl server URL (e.g., https://certctl.example.com):${NC}"
        read -r SERVER_URL || true
        if [[ -z "${SERVER_URL:-}" ]]; then
            echo -e "${RED}Error: Server URL is required${NC}" >&2
            echo "Hint: pass --server-url <URL> to run non-interactively." >&2
            exit 1
        fi
    fi

    if [[ -z "${API_KEY:-}" ]]; then
        echo -e "${YELLOW}Enter certctl API key:${NC}"
        read -rs API_KEY || true
        echo ""
        if [[ -z "${API_KEY:-}" ]]; then
            echo -e "${RED}Error: API key is required${NC}" >&2
            echo "Hint: pass --api-key <KEY> to run non-interactively." >&2
            exit 1
        fi
    fi

    if [[ -z "${AGENT_ID:-}" ]]; then
        local default_agent_id
        default_agent_id="$(hostname)"
        # If stdin is still piped (no /dev/tty was available but SERVER_URL +
        # API_KEY arrived via flags), skip the prompt entirely and use the
        # default — no need to block on an optional value.
        if [[ -t 0 ]]; then
            echo -e "${YELLOW}Enter agent ID (default: $default_agent_id):${NC}"
            read -r AGENT_ID || true
        fi
        if [[ -z "${AGENT_ID:-}" ]]; then
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

# Control plane server URL (HTTPS-only as of v2.2)
CERTCTL_SERVER_URL=$SERVER_URL

# API authentication key
CERTCTL_API_KEY=$API_KEY

# Key generation mode (agent = agent-side keygen, server = server-side for demo only)
CERTCTL_KEYGEN_MODE=agent

# Key storage directory (agent-side keygen)
CERTCTL_KEY_DIR=$key_dir

# ---- Control-plane TLS trust ----
# The certctl server is HTTPS-only (v2.2+). The agent's HTTP client MUST trust the
# server's certificate chain. Pick ONE of the approaches below:
#
#   1) Public CA (Let's Encrypt, DigiCert, etc.) — no config needed; system trust store works.
#   2) Private / enterprise CA — point the agent at the CA bundle that signed the server cert:
# CERTCTL_SERVER_CA_BUNDLE_PATH=/etc/certctl/server-ca.crt
#
#   3) Self-signed server cert (Helm/compose bootstrap) — same env var, just point at the
#      extracted self-signed CA bundle (e.g. from the certctl-server-tls Kubernetes secret
#      via: kubectl get secret certctl-server-tls -o jsonpath='{.data.ca\.crt}' | base64 -d).
#
#   4) Dev/eval only — disable verification entirely (NEVER do this in production):
# CERTCTL_SERVER_TLS_INSECURE_SKIP_VERIFY=true

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

# Control plane server URL (HTTPS-only as of v2.2)
CERTCTL_SERVER_URL=$SERVER_URL

# API authentication key
CERTCTL_API_KEY=$API_KEY

# Key generation mode (agent = agent-side keygen, server = server-side for demo only)
CERTCTL_KEYGEN_MODE=agent

# Key storage directory (agent-side keygen)
CERTCTL_KEY_DIR=$key_dir

# ---- Control-plane TLS trust ----
# The certctl server is HTTPS-only (v2.2+). The agent's HTTP client MUST trust the
# server's certificate chain. Pick ONE of the approaches below:
#
#   1) Public CA (Let's Encrypt, DigiCert, etc.) — no config needed; system trust store works.
#   2) Private / enterprise CA — point the agent at the CA bundle that signed the server cert:
# CERTCTL_SERVER_CA_BUNDLE_PATH=$HOME/.certctl/server-ca.crt
#
#   3) Self-signed server cert (Helm/compose bootstrap) — same env var, just point at the
#      extracted self-signed CA bundle (e.g. from the certctl-server-tls Kubernetes secret
#      via: kubectl get secret certctl-server-tls -o jsonpath='{.data.ca\.crt}' | base64 -d).
#
#   4) Dev/eval only — disable verification entirely (NEVER do this in production):
# CERTCTL_SERVER_TLS_INSECURE_SKIP_VERIFY=true

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
Documentation=https://github.com/certctl-io/certctl
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

    ensure_interactive_input
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
