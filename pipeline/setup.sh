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
        python3-dev \
        python3-full
    
    # For Ubuntu 24.04+ which uses python3.12
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

# Install SAST (Static Application Security Testing) tools for Phase 3
install_sast_tools() {
    log_info "Installing SAST tools for Phase 3 validation..."
    
    # Install Cppcheck
    log_info "Installing Cppcheck..."
    apt-get install -y cppcheck || {
        log_warn "Cppcheck not in apt, attempting manual install..."
        # Install from source if apt fails
        cd /tmp
        git clone https://github.com/danmar/cppcheck.git
        cd cppcheck
        make MATCHCOMPILER=yes FILESDIR=/usr/share/cppcheck HAVE_RULES=yes -j$(nproc)
        make install FILESDIR=/usr/share/cppcheck
        cd /
        rm -rf /tmp/cppcheck
    }
    
    # Verify Cppcheck installation
    if command -v cppcheck &> /dev/null; then
        log_info "Cppcheck installed: $(cppcheck --version)"
    else
        log_error "Cppcheck installation failed"
    fi
    
    # Install Flawfinder
    log_info "Installing Flawfinder..."
    pip3 install flawfinder --break-system-packages 2>/dev/null || \
        pip3 install flawfinder 2>/dev/null || \
        apt-get install -y flawfinder 2>/dev/null || {
            log_warn "Flawfinder installation via pip/apt failed, trying alternative..."
            # Download and install manually
            cd /tmp
            wget https://github.com/david-a-wheeler/flawfinder/archive/refs/heads/master.zip -O flawfinder.zip
            unzip flawfinder.zip
            cd flawfinder-master
            python3 setup.py install 2>/dev/null || pip3 install . --break-system-packages 2>/dev/null
            cd /
            rm -rf /tmp/flawfinder*
        }
    
    # Verify Flawfinder installation
    if command -v flawfinder &> /dev/null; then
        log_info "Flawfinder installed: $(flawfinder --version 2>&1 | head -1)"
    else
        log_error "Flawfinder installation failed"
    fi
    
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
    
    # Cppcheck (Phase 3)
    if command -v cppcheck &> /dev/null; then
        echo -e "Cppcheck:    ${GREEN}✓${NC} $(cppcheck --version)"
    else
        echo -e "Cppcheck:    ${RED}✗ Not installed${NC}"
    fi
    
    # Flawfinder (Phase 3)
    if command -v flawfinder &> /dev/null; then
        echo -e "Flawfinder:  ${GREEN}✓${NC} $(flawfinder --version 2>&1 | head -1)"
    else
        echo -e "Flawfinder:  ${RED}✗ Not installed${NC}"
    fi
    
    echo "============================================="
    echo ""
}

# Create project directory structure
setup_project_structure() {
    log_info "Setting up project directory structure..."
    
    # Get the directory where the script is located
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    
    # Create necessary directories for Phase 1
    mkdir -p "$SCRIPT_DIR/exploits"
    mkdir -p "$SCRIPT_DIR/docker_builds"
    mkdir -p "$SCRIPT_DIR/results"
    mkdir -p "$SCRIPT_DIR/logs"
    
    # Create necessary directories for Phase 2
    mkdir -p "$SCRIPT_DIR/patches"
    
    # Create necessary directories for Phase 3
    mkdir -p "$SCRIPT_DIR/validation_builds"
    mkdir -p "$SCRIPT_DIR/validation_results"
    
    # Create necessary directories for Phase 4
    mkdir -p "$SCRIPT_DIR/reports"
    
    log_info "Project structure created at $SCRIPT_DIR"
}

# Main execution
main() {
    echo ""
    echo "============================================="
    echo "AI-SSD Complete Pipeline Setup"
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
    verify_installations
    
    log_info "Setup completed successfully!"
    log_info "You may need to log out and back in for Docker group changes to take effect."
    echo ""
    echo "Next steps:"
    echo "  Full Pipeline:  python3 pipeline.py --verbose"
    echo "  Phase 1: python3 orchestrator.py --verbose"
    echo "  Phase 2: python3 patch_generator.py --verbose"
    echo "  Phase 3: python3 patch_validator.py --verbose"
    echo "  Phase 4: python3 reporter.py --verbose"
    echo "  Cleanup: python3 cleanup.py --all"
    echo ""
}

# Run main function
main "$@"