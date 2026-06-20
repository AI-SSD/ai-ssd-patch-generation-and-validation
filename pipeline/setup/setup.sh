#!/bin/bash
# =============================================================================
# AI-SSD Project - Server Setup Script
# Phase 1: Vulnerability ID & Setup
# Phase 2: Automated Patch Generation
# Phase 3: Multi-Layered Validation
# Phase 4: Automated Reporting
# Master Pipeline Orchestrator
# =============================================================================
# This script prepares a fresh Ubuntu server with all dependencies needed
# to run the complete AI-SSD pipeline (vulnerability reproduction, patch 
# generation, validation including SAST tools, and automated reporting).
# =============================================================================

set -e  # Exit on any error

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PIPELINE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Pipeline config that points (via its phase0_config key) at the project YAML
# whose SAST tools we install. Override with: sudo ./setup/setup.sh --config <file>
PIPELINE_CONFIG="$PIPELINE_ROOT/config.yaml"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root or with sudo
check_privileges() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root or with sudo"
        exit 1
    fi
}

# Update system packages
update_system() {
    log_info "Updating system packages..."
    apt-get update -y
    apt-get upgrade -y
}

# Install Docker
install_docker() {
    log_info "Installing Docker..."

    # Idempotent guard: if Docker is already installed AND the daemon responds,
    # do NOT reinstall. The reinstall path below runs `rm -rf /var/lib/docker`,
    # which wipes every image/container — destructive to re-run on a live host.
    if command -v docker &> /dev/null && docker info &> /dev/null; then
        log_info "Docker already installed and running — skipping (re)install"
        if [ -n "$SUDO_USER" ]; then
            usermod -aG docker "$SUDO_USER" 2>/dev/null || true
        fi
        return
    fi

    # Remove old versions if present
    apt-get remove -y docker docker-engine docker.io containerd runc 2>/dev/null || true
    
    # Clean up any leftover Docker data that might cause conflicts
    log_info "Cleaning up previous Docker installations..."
    rm -rf /var/lib/docker 2>/dev/null || true
    rm -rf /var/lib/containerd 2>/dev/null || true
    
    # Try Docker's official repo first, fall back to Ubuntu's docker.io if it fails
    if install_docker_official; then
        log_info "Docker installed from official repository"
    else
        log_warn "Official Docker repo failed, falling back to Ubuntu's docker.io package..."
        install_docker_ubuntu
    fi

    # Start and enable Docker service
    log_info "Starting Docker service..."
    systemctl daemon-reload
    systemctl start docker || {
        log_warn "Docker service failed to start, attempting recovery..."
        # Try to fix common issues
        rm -rf /var/lib/docker/network 2>/dev/null || true
        systemctl start docker || {
            log_error "Docker service failed to start. Run 'journalctl -xeu docker.service' for details."
            log_info "You may need to reboot and run the setup again."
        }
    }
    systemctl enable docker

    # Add current user to docker group (if not root)
    if [ -n "$SUDO_USER" ]; then
        usermod -aG docker "$SUDO_USER"
        log_info "Added $SUDO_USER to docker group. Please log out and back in for this to take effect."
    fi

    log_info "Docker installed successfully"
}

# Try installing Docker from official repository
install_docker_official() {
    log_info "Attempting to install Docker from official repository..."
    
    # Install dependencies
    apt-get install -y \
        ca-certificates \
        curl \
        gnupg \
        lsb-release || return 1

    # Add Docker's official GPG key
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --batch --yes --dearmor -o /etc/apt/keyrings/docker.gpg
    chmod a+r /etc/apt/keyrings/docker.gpg

    # Set up repository
    echo \
        "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
        $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
        tee /etc/apt/sources.list.d/docker.list > /dev/null

    # Install Docker Engine
    apt-get update -y
    apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    
    return $?
}

# Fallback: Install Docker from Ubuntu repositories
install_docker_ubuntu() {
    log_info "Installing Docker from Ubuntu repositories (docker.io)..."
    
    # Remove Docker official repo if it exists (might be broken)
    rm -f /etc/apt/sources.list.d/docker.list 2>/dev/null || true
    
    apt-get update -y
    apt-get install -y docker.io docker-compose
    
    if ! command -v docker &> /dev/null; then
        log_error "Failed to install Docker"
        exit 1
    fi
}

# Install Python 3 and pip
install_python() {
    log_info "Installing Python 3 and dependencies..."
    
    apt-get install -y \
        python3 \
        python3-pip \
        python3-venv \
        python3-dev

    # Optional metapackages absent on older releases — install if available,
    # never abort the run when they don't exist (python3-full is 22.04+, focal
    # has no such package; python3.12-venv only on 24.04+).
    apt-get install -y python3-full 2>/dev/null || true
    apt-get install -y python3.12-venv 2>/dev/null || true

    # Install required Python packages (system-wide for root, or use pip with break-system-packages)
    # Using --break-system-packages for Ubuntu 23.04+ which enforces PEP 668
    python3 -m pip install --break-system-packages --upgrade pip 2>/dev/null || \
        python3 -m pip install --upgrade pip 2>/dev/null || true

    # Phase 1 + Phase 2 + Phase 3 + Phase 4 dependencies
    python3 -m pip install --break-system-packages \
        docker \
        pandas \
        pyyaml \
        colorama \
        jinja2 \
        requests \
        openai \
        typing-extensions \
        matplotlib \
        numpy 2>/dev/null || \
    python3 -m pip install \
        docker \
        pandas \
        pyyaml \
        colorama \
        jinja2 \
        requests \
        openai \
        typing-extensions \
        matplotlib \
        numpy 2>/dev/null || true

    log_info "Python 3 installed successfully"
    log_info "Note: For production use, create a virtual environment:"
    log_info "  python3 -m venv venv && source venv/bin/activate && pip install -r requirements.txt"
}

# Install build dependencies for glibc
install_build_deps() {
    log_info "Installing build dependencies..."
    
    apt-get install -y \
        build-essential \
        git \
        wget \
        gawk \
        bison \
        texinfo \
        autoconf \
        libtool \
        pkg-config \
        libgmp-dev \
        libmpfr-dev \
        libmpc-dev \
        flex \
        gettext \
        make \
        gcc \
        g++ \
        binutils

    log_info "Build dependencies installed successfully"
}

# Install SAST (Static Application Security Testing) tools for Phase 3.
#
# The tool list is NOT hardcoded here — it is project-/language-specific and is
# declared in the active project's Phase 0 YAML (sast: section), resolved from
# $PIPELINE_CONFIG via master_pipeline.sast_config. This keeps setup agnostic:
# a C project installs cppcheck/flawfinder, a Java project spotbugs/semgrep, etc.
install_sast_tools() {
    log_info "Installing SAST tools for Phase 3 (from project config: $PIPELINE_CONFIG)..."

    local enabled
    enabled="$(cd "$PIPELINE_ROOT" && python3 -m master_pipeline.sast_config --config "$PIPELINE_CONFIG" --enabled 2>/dev/null)"
    if [ "$enabled" != "true" ]; then
        log_warn "SAST disabled in project config (or config unreadable) — skipping SAST tool installation"
        return
    fi

    # First, report current state — tools already present are left untouched.
    local any_missing=0 any_tool=0
    while IFS=$'\t' read -r name status hint; do
        [ -z "$name" ] && continue
        any_tool=1
        if [ "$status" = "OK" ]; then
            log_info "SAST tool '$name': already installed — skipping"
        else
            any_missing=1
            log_info "SAST tool '$name': missing — will install ($hint)"
        fi
    done < <(cd "$PIPELINE_ROOT" && python3 -m master_pipeline.sast_config --config "$PIPELINE_CONFIG" --check 2>/dev/null)

    if [ "$any_tool" -eq 0 ]; then
        log_warn "No SAST tools declared in project config"
        return
    fi
    if [ "$any_missing" -eq 0 ]; then
        log_info "All configured SAST tools already present — nothing to install"
        return
    fi

    # Install ONLY the missing tools (--missing-only filters out present ones).
    while IFS=$'\t' read -r name method spec; do
        [ -z "$name" ] && continue
        log_info "Installing SAST tool '$name' ($method)..."
        case "$method" in
            apt)
                apt-get install -y "$spec" || log_warn "apt install '$spec' failed for $name"
                ;;
            pip)
                pip3 install "$spec" --break-system-packages 2>/dev/null \
                    || pip3 install "$spec" 2>/dev/null \
                    || log_warn "pip install '$spec' failed for $name"
                ;;
            script)
                bash -c "$spec" || log_warn "script install failed for $name"
                ;;
            *)
                log_warn "Unknown install method '$method' for $name — install it manually"
                ;;
        esac
    done < <(cd "$PIPELINE_ROOT" && python3 -m master_pipeline.sast_config --config "$PIPELINE_CONFIG" --list-install --missing-only 2>/dev/null)

    # Final verification — every configured tool must now resolve.
    log_info "Verifying SAST tools..."
    while IFS=$'\t' read -r name status hint; do
        [ -z "$name" ] && continue
        if [ "$status" = "OK" ]; then
            log_info "SAST tool '$name': installed"
        else
            log_error "SAST tool '$name': NOT installed ($hint)"
        fi
    done < <(cd "$PIPELINE_ROOT" && python3 -m master_pipeline.sast_config --config "$PIPELINE_CONFIG" --check 2>/dev/null)

    log_info "SAST tools installation completed"
}

#!/bin/bash
# =============================================================================
# AI-SSD Project - Server Setup Script
# Phase 1: Vulnerability ID & Setup
# Phase 2: Automated Patch Generation
# Phase 3: Multi-Layered Validation
# Phase 4: Automated Reporting
# Master Pipeline Orchestrator
# =============================================================================
# This script prepares a fresh Ubuntu server with all dependencies needed
# to run the complete AI-SSD pipeline (vulnerability reproduction, patch 
# generation, validation including SAST tools, and automated reporting).
# =============================================================================

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root or with sudo
check_privileges() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root or with sudo"
        exit 1
    fi
}

# Update system packages
update_system() {
    log_info "Updating system packages..."
    apt-get update -y
    apt-get upgrade -y
}

# Install Docker
install_docker() {
    log_info "Installing Docker..."

    # Idempotent guard: if Docker is already installed AND the daemon responds,
    # do NOT reinstall. The reinstall path below runs `rm -rf /var/lib/docker`,
    # which wipes every image/container — destructive to re-run on a live host.
    if command -v docker &> /dev/null && docker info &> /dev/null; then
        log_info "Docker already installed and running — skipping (re)install"
        if [ -n "$SUDO_USER" ]; then
            usermod -aG docker "$SUDO_USER" 2>/dev/null || true
        fi
        return
    fi

    # Remove old versions if present
    apt-get remove -y docker docker-engine docker.io containerd runc 2>/dev/null || true
    
    # Clean up any leftover Docker data that might cause conflicts
    log_info "Cleaning up previous Docker installations..."
    rm -rf /var/lib/docker 2>/dev/null || true
    rm -rf /var/lib/containerd 2>/dev/null || true
    
    # Try Docker's official repo first, fall back to Ubuntu's docker.io if it fails
    if install_docker_official; then
        log_info "Docker installed from official repository"
    else
        log_warn "Official Docker repo failed, falling back to Ubuntu's docker.io package..."
        install_docker_ubuntu
    fi

    # Start and enable Docker service
    log_info "Starting Docker service..."
    systemctl daemon-reload
    systemctl start docker || {
        log_warn "Docker service failed to start, attempting recovery..."
        # Try to fix common issues
        rm -rf /var/lib/docker/network 2>/dev/null || true
        systemctl start docker || {
            log_error "Docker service failed to start. Run 'journalctl -xeu docker.service' for details."
            log_info "You may need to reboot and run the setup again."
        }
    }
    systemctl enable docker

    # Add current user to docker group (if not root)
    if [ -n "$SUDO_USER" ]; then
        usermod -aG docker "$SUDO_USER"
        log_info "Added $SUDO_USER to docker group. Please log out and back in for this to take effect."
    fi

    log_info "Docker installed successfully"
}

# Try installing Docker from official repository
install_docker_official() {
    log_info "Attempting to install Docker from official repository..."
    
    # Install dependencies
    apt-get install -y \
        ca-certificates \
        curl \
        gnupg \
        lsb-release || return 1

    # Add Docker's official GPG key
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --batch --yes --dearmor -o /etc/apt/keyrings/docker.gpg
    chmod a+r /etc/apt/keyrings/docker.gpg

    # Set up repository
    echo \
        "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
        $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
        tee /etc/apt/sources.list.d/docker.list > /dev/null

    # Install Docker Engine
    apt-get update -y
    apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    
    return $?
}

# Fallback: Install Docker from Ubuntu repositories
install_docker_ubuntu() {
    log_info "Installing Docker from Ubuntu repositories (docker.io)..."
    
    # Remove Docker official repo if it exists (might be broken)
    rm -f /etc/apt/sources.list.d/docker.list 2>/dev/null || true
    
    apt-get update -y
    apt-get install -y docker.io docker-compose
    
    if ! command -v docker &> /dev/null; then
        log_error "Failed to install Docker"
        exit 1
    fi
}

# Install Python 3 and pip
install_python() {
    log_info "Installing Python 3 and dependencies..."
    
    apt-get install -y \
        python3 \
        python3-pip \
        python3-venv \
        python3-dev

    # Optional metapackages absent on older releases — install if available,
    # never abort the run when they don't exist (python3-full is 22.04+, focal
    # has no such package; python3.12-venv only on 24.04+).
    apt-get install -y python3-full 2>/dev/null || true
    apt-get install -y python3.12-venv 2>/dev/null || true

    # Install required Python packages (system-wide for root, or use pip with break-system-packages)
    # Using --break-system-packages for Ubuntu 23.04+ which enforces PEP 668
    python3 -m pip install --break-system-packages --upgrade pip 2>/dev/null || \
        python3 -m pip install --upgrade pip 2>/dev/null || true

    # Phase 1 + Phase 2 + Phase 3 + Phase 4 dependencies
    python3 -m pip install --break-system-packages \
        docker \
        pandas \
        pyyaml \
        colorama \
        jinja2 \
        requests \
        openai \
        typing-extensions \
        matplotlib \
        numpy 2>/dev/null || \
    python3 -m pip install \
        docker \
        pandas \
        pyyaml \
        colorama \
        jinja2 \
        requests \
        openai \
        typing-extensions \
        matplotlib \
        numpy 2>/dev/null || true

    log_info "Python 3 installed successfully"
    log_info "Note: For production use, create a virtual environment:"
    log_info "  python3 -m venv venv && source venv/bin/activate && pip install -r requirements.txt"
}

# Install build dependencies for glibc
install_build_deps() {
    log_info "Installing build dependencies..."
    
    apt-get install -y \
        build-essential \
        git \
        wget \
        gawk \
        bison \
        texinfo \
        autoconf \
        libtool \
        pkg-config \
        libgmp-dev \
        libmpfr-dev \
        libmpc-dev \
        flex \
        gettext \
        make \
        gcc \
        g++ \
        binutils

    log_info "Build dependencies installed successfully"
}

# Install SAST (Static Application Security Testing) tools for Phase 3.
#
# The tool list is NOT hardcoded here — it is project-/language-specific and is
# declared in the active project's Phase 0 YAML (sast: section), resolved from
# $PIPELINE_CONFIG via master_pipeline.sast_config. This keeps setup agnostic:
# a C project installs cppcheck/flawfinder, a Java project spotbugs/semgrep, etc.
install_sast_tools() {
    log_info "Installing SAST tools for Phase 3 (from project config: $PIPELINE_CONFIG)..."

    local enabled
    enabled="$(cd "$PIPELINE_ROOT" && python3 -m master_pipeline.sast_config --config "$PIPELINE_CONFIG" --enabled 2>/dev/null)"
    if [ "$enabled" != "true" ]; then
        log_warn "SAST disabled in project config (or config unreadable) — skipping SAST tool installation"
        return
    fi

    # First, report current state — tools already present are left untouched.
    local any_missing=0 any_tool=0
    while IFS=$'\t' read -r name status hint; do
        [ -z "$name" ] && continue
        any_tool=1
        if [ "$status" = "OK" ]; then
            log_info "SAST tool '$name': already installed — skipping"
        else
            any_missing=1
            log_info "SAST tool '$name': missing — will install ($hint)"
        fi
    done < <(cd "$PIPELINE_ROOT" && python3 -m master_pipeline.sast_config --config "$PIPELINE_CONFIG" --check 2>/dev/null)

    if [ "$any_tool" -eq 0 ]; then
        log_warn "No SAST tools declared in project config"
        return
    fi
    if [ "$any_missing" -eq 0 ]; then
        log_info "All configured SAST tools already present — nothing to install"
        return
    fi

    # Install ONLY the missing tools (--missing-only filters out present ones).
    while IFS=$'\t' read -r name method spec; do
        [ -z "$name" ] && continue
        log_info "Installing SAST tool '$name' ($method)..."
        case "$method" in
            apt)
                apt-get install -y "$spec" || log_warn "apt install '$spec' failed for $name"
                ;;
            pip)
                pip3 install "$spec" --break-system-packages 2>/dev/null \
                    || pip3 install "$spec" 2>/dev/null \
                    || log_warn "pip install '$spec' failed for $name"
                ;;
            script)
                bash -c "$spec" || log_warn "script install failed for $name"
                ;;
            *)
                log_warn "Unknown install method '$method' for $name — install it manually"
                ;;
        esac
    done < <(cd "$PIPELINE_ROOT" && python3 -m master_pipeline.sast_config --config "$PIPELINE_CONFIG" --list-install --missing-only 2>/dev/null)

    # Final verification — every configured tool must now resolve.
    log_info "Verifying SAST tools..."
    while IFS=$'\t' read -r name status hint; do
        [ -z "$name" ] && continue
        if [ "$status" = "OK" ]; then
            log_info "SAST tool '$name': installed"
        else
            log_error "SAST tool '$name': NOT installed ($hint)"
        fi
    done < <(cd "$PIPELINE_ROOT" && python3 -m master_pipeline.sast_config --config "$PIPELINE_CONFIG" --check 2>/dev/null)

    log_info "SAST tools installation completed"
}

# Install additional utilities
install_utilities() {
    log_info "Installing additional utilities..."
    
    apt-get install -y \
        jq \
        tree \
        htop \
        vim \
        tmux \
        unzip \
        zip

    log_info "Utilities installed successfully"
}

# Setup API Keys
setup_api_keys() {
    log_info "Setting up API keys files..."
    
    if [ ! -f "$PIPELINE_ROOT/API-nvd-key" ]; then
        touch "$PIPELINE_ROOT/API-nvd-key"
        chmod 600 "$PIPELINE_ROOT/API-nvd-key"
        if [ -n "$SUDO_USER" ]; then
            chown "$SUDO_USER:$SUDO_USER" "$PIPELINE_ROOT/API-nvd-key"
        fi
        log_info "Created empty API-nvd-key file at $PIPELINE_ROOT/API-nvd-key. Please populate it with your NVD API key."
    else
        log_info "API-nvd-key already exists."
    fi

    if [ ! -f "$PIPELINE_ROOT/API-openai-key" ]; then
        touch "$PIPELINE_ROOT/API-openai-key"
        chmod 600 "$PIPELINE_ROOT/API-openai-key"
        if [ -n "$SUDO_USER" ]; then
            chown "$SUDO_USER:$SUDO_USER" "$PIPELINE_ROOT/API-openai-key"
        fi
        log_info "Created empty API-openai-key file at $PIPELINE_ROOT/API-openai-key. Please populate it with your OpenAI API key."
    else
        log_info "API-openai-key already exists."
    fi
}

# Verify installations
verify_installations() {
    log_info "Verifying installations..."
    
    echo ""
    echo "============================================="
    echo "Installation Verification"
    echo "============================================="
    
    # Docker
    if command -v docker &> /dev/null; then
        echo -e "Docker:      ${GREEN}✓${NC} $(docker --version)"
    else
        echo -e "Docker:      ${RED}✗ Not installed${NC}"
    fi
    
    # Python
    if command -v python3 &> /dev/null; then
        echo -e "Python3:     ${GREEN}✓${NC} $(python3 --version)"
    else
        echo -e "Python3:     ${RED}✗ Not installed${NC}"
    fi
    
    # pip
    if command -v pip3 &> /dev/null; then
        echo -e "pip3:        ${GREEN}✓${NC} $(pip3 --version | cut -d' ' -f1-2)"
    else
        echo -e "pip3:        ${RED}✗ Not installed${NC}"
    fi
    
    # Git
    if command -v git &> /dev/null; then
        echo -e "Git:         ${GREEN}✓${NC} $(git --version)"
    else
        echo -e "Git:         ${RED}✗ Not installed${NC}"
    fi
    
    # GCC
    if command -v gcc &> /dev/null; then
        echo -e "GCC:         ${GREEN}✓${NC} $(gcc --version | head -1)"
    else
        echo -e "GCC:         ${RED}✗ Not installed${NC}"
    fi
    
    # SAST tools (Phase 3) — driven by the project YAML's sast: section
    if [ "$(cd "$PIPELINE_ROOT" && python3 -m master_pipeline.sast_config --config "$PIPELINE_CONFIG" --enabled 2>/dev/null)" = "true" ]; then
        while IFS=$'\t' read -r name status hint; do
            [ -z "$name" ] && continue
            if [ "$status" = "OK" ]; then
                echo -e "SAST $name: ${GREEN}✓${NC} installed"
            else
                echo -e "SAST $name: ${RED}✗ Not installed${NC} ($hint)"
            fi
        done < <(cd "$PIPELINE_ROOT" && python3 -m master_pipeline.sast_config --config "$PIPELINE_CONFIG" --check 2>/dev/null)
    else
        echo -e "SAST:        ${YELLOW}disabled in project config${NC}"
    fi

    echo "============================================="
    echo ""
}

# Create project directory structure
setup_project_structure() {
    log_info "Setting up project directory structure..."

    # Create necessary directories for Phase 1
    mkdir -p "$PIPELINE_ROOT/exploits"
    mkdir -p "$PIPELINE_ROOT/docker_builds"
    mkdir -p "$PIPELINE_ROOT/results"
    mkdir -p "$PIPELINE_ROOT/logs"
    
    # Create necessary directories for Phase 2
    mkdir -p "$PIPELINE_ROOT/patches"
    
    # Create necessary directories for Phase 3
    mkdir -p "$PIPELINE_ROOT/validation_builds"
    mkdir -p "$PIPELINE_ROOT/validation_results"
    
    # Create necessary directories for Phase 4
    mkdir -p "$PIPELINE_ROOT/reports"
    
    # Clone ExploitDB repository if not present (required for Phase 0 PoC matching)
    if [ ! -d "$PIPELINE_ROOT/exploit-database" ]; then
        log_info "Cloning ExploitDB repository (required for Phase 0)..."
        git clone --depth=1 https://gitlab.com/exploit-database/exploitdb.git "$PIPELINE_ROOT/exploit-database" || {
            log_warn "ExploitDB clone failed. Phase 0 will attempt to clone it at runtime."
        }
    else
        log_info "ExploitDB repository already present"
    fi
    
    # Ensure directories have proper ownership if running with sudo
    if [ -n "$SUDO_USER" ]; then
        chown -R "$SUDO_USER:$SUDO_USER" "$PIPELINE_ROOT/exploits" "$PIPELINE_ROOT/docker_builds" "$PIPELINE_ROOT/results" "$PIPELINE_ROOT/logs" "$PIPELINE_ROOT/patches" "$PIPELINE_ROOT/validation_builds" "$PIPELINE_ROOT/validation_results" "$PIPELINE_ROOT/reports" 2>/dev/null || true
    fi
    
    log_info "Project structure created at $PIPELINE_ROOT"
}

# Main execution
main() {
    # Parse args — only --config so far: selects the pipeline config whose
    # phase0_config points at the project YAML whose SAST tools we install.
    while [ $# -gt 0 ]; do
        case "$1" in
            --config) PIPELINE_CONFIG="$2"; shift 2 ;;
            --config=*) PIPELINE_CONFIG="${1#*=}"; shift ;;
            *) shift ;;
        esac
    done

    echo ""
    echo "============================================="
    echo "AI-SSD Complete Pipeline Setup"
    echo "Phase 0: Data Aggregation"
    echo "Phase 1: Vulnerability Reproduction"
    echo "Phase 2: Automated Patch Generation"
    echo "Phase 3: Multi-Layered Validation"
    echo "Phase 4: Automated Reporting"
    echo "Master Pipeline Orchestrator"
    echo "============================================="
    echo ""
    
    check_privileges
    update_system
    install_docker
    install_python
    install_build_deps
    install_sast_tools
    install_utilities
    setup_project_structure
    setup_api_keys
    verify_installations
    
    log_info "Setup completed successfully!"
    log_info "You may need to log out and back in for Docker group changes to take effect."
    log_warn "Please ensure you add your API keys to pipeline/API-nvd-key and pipeline/API-openai-key"
    echo ""
    echo "Next steps:"
    echo "  Full Pipeline:  python3 pipeline.py --verbose"
    echo "  Phase 0: python3 pipeline.py --phases 0 --verbose"
    echo "  Phase 1: python3 orchestrator.py --verbose"
    echo "  Phase 2: python3 patch_generator.py --verbose"
    echo "  Phase 3: python3 patch_validator.py --verbose"
    echo "  Phase 4: python3 reporter.py --verbose"
    echo "  Cleanup: python3 cleanup.py --all"
    echo ""
}

# Run main function
main "$@"
