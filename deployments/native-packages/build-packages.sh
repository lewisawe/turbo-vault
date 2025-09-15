#!/bin/bash

# Build script for creating native binary packages for Vault Agent
# Supports Linux, Windows, and macOS across multiple architectures

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
VAULT_AGENT_DIR="${PROJECT_ROOT}/vault-agent"
BUILD_DIR="${SCRIPT_DIR}/build"
DIST_DIR="${SCRIPT_DIR}/dist"

# Version information
VERSION="${VERSION:-$(git describe --tags --always --dirty)}"
BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
GIT_COMMIT="$(git rev-parse HEAD)"

# Build targets
TARGETS=(
    "linux/amd64"
    "linux/arm64"
    "linux/386"
    "darwin/amd64"
    "darwin/arm64"
    "windows/amd64"
    "windows/386"
)

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Check dependencies
check_dependencies() {
    log "Checking dependencies..."
    
    if ! command -v go &> /dev/null; then
        error "Go is not installed or not in PATH"
        exit 1
    fi
    
    if ! command -v git &> /dev/null; then
        error "Git is not installed or not in PATH"
        exit 1
    fi
    
    # Check for packaging tools
    local missing_tools=()
    
    if ! command -v fpm &> /dev/null; then
        missing_tools+=("fpm")
    fi
    
    if ! command -v rpmbuild &> /dev/null; then
        missing_tools+=("rpmbuild")
    fi
    
    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        warn "Some packaging tools are missing: ${missing_tools[*]}"
        warn "Install them for full packaging support:"
        warn "  - fpm: gem install fpm"
        warn "  - rpmbuild: yum install rpm-build (RHEL/CentOS) or apt-get install rpm (Debian/Ubuntu)"
    fi
    
    success "Dependencies check completed"
}

# Clean build directories
clean() {
    log "Cleaning build directories..."
    rm -rf "${BUILD_DIR}" "${DIST_DIR}"
    mkdir -p "${BUILD_DIR}" "${DIST_DIR}"
    success "Build directories cleaned"
}

# Build binary for specific target
build_binary() {
    local target="$1"
    local goos="${target%/*}"
    local goarch="${target#*/}"
    
    log "Building binary for ${goos}/${goarch}..."
    
    local binary_name="vault-agent"
    if [[ "${goos}" == "windows" ]]; then
        binary_name="vault-agent.exe"
    fi
    
    local output_dir="${BUILD_DIR}/${goos}-${goarch}"
    mkdir -p "${output_dir}"
    
    # Build with optimizations and version info
    cd "${VAULT_AGENT_DIR}"
    
    CGO_ENABLED=0 GOOS="${goos}" GOARCH="${goarch}" go build \
        -ldflags="-w -s -X main.version=${VERSION} -X main.buildDate=${BUILD_DATE} -X main.gitCommit=${GIT_COMMIT}" \
        -o "${output_dir}/${binary_name}" \
        ./main.go
    
    # Copy additional files
    cp -r "${PROJECT_ROOT}/README.md" "${output_dir}/"
    cp -r "${PROJECT_ROOT}/LICENSE" "${output_dir}/" 2>/dev/null || true
    
    # Create config directory and sample config
    mkdir -p "${output_dir}/config"
    cat > "${output_dir}/config/vault-agent.yaml" << 'EOF'
# Vault Agent Configuration
server:
  bind_address: "0.0.0.0:8200"
  tls_cert_file: ""
  tls_key_file: ""
  log_level: "info"

storage:
  type: "sqlite"
  connection_string: "./vault-agent.db"

cache:
  type: "memory"
  ttl: "5m"

backup:
  enabled: true
  schedule: "0 2 * * *"
  retention_days: 30
EOF
    
    # Create systemd service file for Linux
    if [[ "${goos}" == "linux" ]]; then
        mkdir -p "${output_dir}/systemd"
        cat > "${output_dir}/systemd/vault-agent.service" << 'EOF'
[Unit]
Description=Vault Agent - Decentralized Key Management
Documentation=https://vault-agent.com/docs
After=network.target
Wants=network.target

[Service]
Type=simple
User=vault-agent
Group=vault-agent
ExecStart=/usr/local/bin/vault-agent server --config /etc/vault-agent/vault-agent.yaml
ExecReload=/bin/kill -HUP $MAINPID
KillMode=process
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

# Security settings
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/vault-agent
CapabilityBoundingSet=CAP_IPC_LOCK
AmbientCapabilities=CAP_IPC_LOCK
SecureBits=keep-caps

[Install]
WantedBy=multi-user.target
EOF
    fi
    
    # Create Windows service installer for Windows
    if [[ "${goos}" == "windows" ]]; then
        mkdir -p "${output_dir}/windows"
        cat > "${output_dir}/windows/install-service.bat" << 'EOF'
@echo off
echo Installing Vault Agent Windows Service...

sc create VaultAgent binPath= "%~dp0vault-agent.exe server --config %~dp0config\vault-agent.yaml" DisplayName= "Vault Agent" start= auto
sc description VaultAgent "Vault Agent - Decentralized Key Management Platform"

echo Service installed successfully.
echo Use 'sc start VaultAgent' to start the service.
pause
EOF
        
        cat > "${output_dir}/windows/uninstall-service.bat" << 'EOF'
@echo off
echo Uninstalling Vault Agent Windows Service...

sc stop VaultAgent
sc delete VaultAgent

echo Service uninstalled successfully.
pause
EOF
    fi
    
    success "Binary built for ${goos}/${goarch}"
}

# Create archive for target
create_archive() {
    local target="$1"
    local goos="${target%/*}"
    local goarch="${target#*/}"
    
    log "Creating archive for ${goos}/${goarch}..."
    
    local source_dir="${BUILD_DIR}/${goos}-${goarch}"
    local archive_name="vault-agent-${VERSION}-${goos}-${goarch}"
    
    cd "${BUILD_DIR}"
    
    if [[ "${goos}" == "windows" ]]; then
        # Create ZIP for Windows
        zip -r "${DIST_DIR}/${archive_name}.zip" "${goos}-${goarch}"
    else
        # Create tar.gz for Unix-like systems
        tar -czf "${DIST_DIR}/${archive_name}.tar.gz" "${goos}-${goarch}"
    fi
    
    success "Archive created: ${archive_name}"
}

# Create DEB package for Debian/Ubuntu
create_deb_package() {
    if ! command -v fpm &> /dev/null; then
        warn "fpm not available, skipping DEB package creation"
        return
    fi
    
    log "Creating DEB package..."
    
    local source_dir="${BUILD_DIR}/linux-amd64"
    local package_name="vault-agent"
    local package_version="${VERSION#v}"  # Remove 'v' prefix if present
    
    fpm -s dir -t deb \
        --name "${package_name}" \
        --version "${package_version}" \
        --description "Vault Agent - Decentralized Key Management Platform" \
        --url "https://vault-agent.com" \
        --maintainer "Vault Agent Team <support@vault-agent.com>" \
        --license "MIT" \
        --architecture "amd64" \
        --depends "systemd" \
        --after-install "${SCRIPT_DIR}/scripts/postinstall.sh" \
        --before-remove "${SCRIPT_DIR}/scripts/preremove.sh" \
        --config-files "/etc/vault-agent/vault-agent.yaml" \
        "${source_dir}/vault-agent=/usr/local/bin/vault-agent" \
        "${source_dir}/config/vault-agent.yaml=/etc/vault-agent/vault-agent.yaml" \
        "${source_dir}/systemd/vault-agent.service=/lib/systemd/system/vault-agent.service" \
        --package "${DIST_DIR}/"
    
    success "DEB package created"
}

# Create RPM package for RHEL/CentOS/Fedora
create_rpm_package() {
    if ! command -v fpm &> /dev/null; then
        warn "fpm not available, skipping RPM package creation"
        return
    fi
    
    log "Creating RPM package..."
    
    local source_dir="${BUILD_DIR}/linux-amd64"
    local package_name="vault-agent"
    local package_version="${VERSION#v}"  # Remove 'v' prefix if present
    
    fpm -s dir -t rpm \
        --name "${package_name}" \
        --version "${package_version}" \
        --description "Vault Agent - Decentralized Key Management Platform" \
        --url "https://vault-agent.com" \
        --maintainer "Vault Agent Team <support@vault-agent.com>" \
        --license "MIT" \
        --architecture "x86_64" \
        --depends "systemd" \
        --after-install "${SCRIPT_DIR}/scripts/postinstall.sh" \
        --before-remove "${SCRIPT_DIR}/scripts/preremove.sh" \
        --config-files "/etc/vault-agent/vault-agent.yaml" \
        "${source_dir}/vault-agent=/usr/local/bin/vault-agent" \
        "${source_dir}/config/vault-agent.yaml=/etc/vault-agent/vault-agent.yaml" \
        "${source_dir}/systemd/vault-agent.service=/lib/systemd/system/vault-agent.service" \
        --package "${DIST_DIR}/"
    
    success "RPM package created"
}

# Create macOS package
create_macos_package() {
    if [[ "$(uname)" != "Darwin" ]]; then
        warn "Not running on macOS, skipping macOS package creation"
        return
    fi
    
    log "Creating macOS package..."
    
    local source_dir="${BUILD_DIR}/darwin-amd64"
    local pkg_root="${BUILD_DIR}/macos-pkg-root"
    
    mkdir -p "${pkg_root}/usr/local/bin"
    mkdir -p "${pkg_root}/etc/vault-agent"
    mkdir -p "${pkg_root}/Library/LaunchDaemons"
    
    # Copy files
    cp "${source_dir}/vault-agent" "${pkg_root}/usr/local/bin/"
    cp "${source_dir}/config/vault-agent.yaml" "${pkg_root}/etc/vault-agent/"
    
    # Create LaunchDaemon plist
    cat > "${pkg_root}/Library/LaunchDaemons/com.vault-agent.vault-agent.plist" << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.vault-agent.vault-agent</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/vault-agent</string>
        <string>server</string>
        <string>--config</string>
        <string>/etc/vault-agent/vault-agent.yaml</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/var/log/vault-agent.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/vault-agent.log</string>
</dict>
</plist>
EOF
    
    # Build package
    pkgbuild --root "${pkg_root}" \
        --identifier "com.vault-agent.vault-agent" \
        --version "${VERSION}" \
        --install-location "/" \
        "${DIST_DIR}/vault-agent-${VERSION}-darwin-amd64.pkg"
    
    success "macOS package created"
}

# Create installation scripts
create_scripts() {
    log "Creating installation scripts..."
    
    mkdir -p "${SCRIPT_DIR}/scripts"
    
    # Post-install script
    cat > "${SCRIPT_DIR}/scripts/postinstall.sh" << 'EOF'
#!/bin/bash

# Create vault-agent user and group
if ! getent group vault-agent >/dev/null 2>&1; then
    groupadd --system vault-agent
fi

if ! getent passwd vault-agent >/dev/null 2>&1; then
    useradd --system --gid vault-agent --home-dir /var/lib/vault-agent --shell /bin/false vault-agent
fi

# Create data directory
mkdir -p /var/lib/vault-agent
chown vault-agent:vault-agent /var/lib/vault-agent
chmod 750 /var/lib/vault-agent

# Create log directory
mkdir -p /var/log/vault-agent
chown vault-agent:vault-agent /var/log/vault-agent
chmod 750 /var/log/vault-agent

# Set permissions
chmod +x /usr/local/bin/vault-agent
chown root:root /usr/local/bin/vault-agent

# Reload systemd and enable service
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload
    systemctl enable vault-agent
    echo "Vault Agent service enabled. Start with: systemctl start vault-agent"
fi

echo "Vault Agent installation completed successfully!"
EOF

    # Pre-remove script
    cat > "${SCRIPT_DIR}/scripts/preremove.sh" << 'EOF'
#!/bin/bash

# Stop and disable service
if command -v systemctl >/dev/null 2>&1; then
    systemctl stop vault-agent || true
    systemctl disable vault-agent || true
fi

echo "Vault Agent service stopped and disabled"
EOF

    chmod +x "${SCRIPT_DIR}/scripts/"*.sh
    
    success "Installation scripts created"
}

# Generate checksums
generate_checksums() {
    log "Generating checksums..."
    
    cd "${DIST_DIR}"
    
    # Generate SHA256 checksums
    if command -v sha256sum &> /dev/null; then
        sha256sum * > checksums.sha256
    elif command -v shasum &> /dev/null; then
        shasum -a 256 * > checksums.sha256
    else
        warn "No SHA256 utility found, skipping checksum generation"
        return
    fi
    
    success "Checksums generated"
}

# Main build function
main() {
    log "Starting Vault Agent native package build..."
    log "Version: ${VERSION}"
    log "Build Date: ${BUILD_DATE}"
    log "Git Commit: ${GIT_COMMIT}"
    
    check_dependencies
    clean
    create_scripts
    
    # Build binaries for all targets
    for target in "${TARGETS[@]}"; do
        build_binary "${target}"
        create_archive "${target}"
    done
    
    # Create native packages
    create_deb_package
    create_rpm_package
    create_macos_package
    
    generate_checksums
    
    # Display results
    log "Build completed successfully!"
    log "Artifacts created in: ${DIST_DIR}"
    
    echo
    success "Available packages:"
    ls -la "${DIST_DIR}"
    
    echo
    log "To install packages:"
    echo "  DEB: sudo dpkg -i vault-agent_*.deb"
    echo "  RPM: sudo rpm -i vault-agent-*.rpm"
    echo "  macOS: sudo installer -pkg vault-agent-*.pkg -target /"
    echo "  Archives: Extract and run ./vault-agent"
}

# Handle command line arguments
case "${1:-}" in
    clean)
        clean
        ;;
    checksums)
        generate_checksums
        ;;
    *)
        main "$@"
        ;;
esac