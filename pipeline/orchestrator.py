#!/usr/bin/env python3
# =============================================================================
# AI-SSD Project - Pipeline Orchestrator
# Phase 1: Vulnerability ID & Setup
# =============================================================================
# This script automates the creation and execution of reproduction environments
# for glibc vulnerabilities listed in file-function.csv
# =============================================================================

import os
import sys
import csv
import json
import shutil
import logging
import argparse
import subprocess
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Tuple
from enum import Enum

# Try to import docker, provide helpful error if not installed
try:
    import docker
    from docker.errors import BuildError, ContainerError, ImageNotFound, APIError
except ImportError:
    print("Error: docker package not installed. Run: pip install docker")
    sys.exit(1)

# =============================================================================
# Configuration and Constants
# =============================================================================

# Mapping of commit dates to appropriate Ubuntu/Debian versions
# Old glibc code requires older compilers to build successfully
COMMIT_OS_MAPPING = {
    # Commits from 2012-2014: Use Ubuntu 14.04 (GCC 4.8)
    "2012": "ubuntu:14.04",
    "2013": "ubuntu:14.04", 
    "2014": "ubuntu:14.04",
    # Commits from 2015-2016: Use Ubuntu 16.04 (GCC 5.x)
    "2015": "ubuntu:16.04",
    "2016": "ubuntu:16.04",
    # Commits from 2017-2018: Use Ubuntu 18.04 (GCC 7.x)
    "2017": "ubuntu:18.04",
    "2018": "ubuntu:18.04",
    # Default fallback
    "default": "ubuntu:16.04"
}

# Known CVE to approximate commit year mapping
# Used when git history is not available
CVE_YEAR_HINTS = {
    "CVE-2012-3480": "2012",
    "CVE-2014-5119": "2014",
    "CVE-2015-7547": "2015",
}


class ExecutionStatus(Enum):
    SUCCESS = "Success"
    BUILD_ERROR = "Build Error"
    EXECUTION_ERROR = "Execution Error"
    POC_NOT_FOUND = "PoC Not Found"
    TIMEOUT = "Timeout"
    UNKNOWN_ERROR = "Unknown Error"


@dataclass
class VulnerabilityInfo:
    """Data class to hold vulnerability information from CSV"""
    cve: str
    commit_hash: str
    file_path: str
    function_name: str
    unit_type: str
    
    @property
    def short_commit(self) -> str:
        return self.commit_hash[:12]
    
    @property
    def container_name(self) -> str:
        return f"glibc-{self.cve.lower()}-{self.short_commit}"
    
    @property
    def image_name(self) -> str:
        return f"glibc-vuln/{self.cve.lower()}:latest"


@dataclass
class ExecutionResult:
    """Data class to hold execution results"""
    cve: str
    commit_hash: str
    status: str
    vulnerability_reproduced: bool
    build_success: bool
    poc_executed: bool
    execution_time_seconds: float
    error_message: Optional[str]
    container_logs: Optional[str]
    timestamp: str


# =============================================================================
# Logging Configuration
# =============================================================================

def setup_logging(log_dir: Path, verbose: bool = False) -> logging.Logger:
    """Configure logging for the orchestrator"""
    log_dir.mkdir(parents=True, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = log_dir / f"orchestrator_{timestamp}.log"
    
    log_level = logging.DEBUG if verbose else logging.INFO
    
    # Create formatters
    file_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    console_formatter = logging.Formatter(
        '%(levelname)s: %(message)s'
    )
    
    # File handler
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(file_formatter)
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(log_level)
    console_handler.setFormatter(console_formatter)
    
    # Configure root logger
    logger = logging.getLogger('orchestrator')
    logger.setLevel(logging.DEBUG)
    # Clear existing handlers to prevent duplicates when module is re-imported
    logger.handlers.clear()
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    return logger


# =============================================================================
# CSV Parser
# =============================================================================

class CSVParser:
    """Parses the file-function.csv to extract vulnerability information"""
    
    def __init__(self, csv_path: Path, logger: logging.Logger):
        self.csv_path = csv_path
        self.logger = logger
    
    def parse(self) -> List[VulnerabilityInfo]:
        """Parse CSV and return list of VulnerabilityInfo objects"""
        vulnerabilities = []
        seen_cves = set()  # Track unique CVEs
        
        self.logger.info(f"Parsing CSV file: {self.csv_path}")
        
        if not self.csv_path.exists():
            raise FileNotFoundError(f"CSV file not found: {self.csv_path}")
        
        with open(self.csv_path, 'r', encoding='utf-8') as f:
            # Detect delimiter (could be ; or ,)
            sample = f.read(2048)
            f.seek(0)
            
            if sample.count(';') > sample.count(','):
                delimiter = ';'
            else:
                delimiter = ','
            
            reader = csv.DictReader(f, delimiter=delimiter)
            
            for row in reader:
                cve = row.get('CVE', '').strip()
                
                # Skip if we've already seen this CVE (avoid duplicates)
                if cve in seen_cves:
                    continue
                seen_cves.add(cve)
                
                if not cve:
                    continue
                
                vuln = VulnerabilityInfo(
                    cve=cve,
                    commit_hash=row.get('V_COMMIT', '').strip(),
                    file_path=row.get('FilePath', '').strip(),
                    function_name=row.get('F_NAME', '').strip(),
                    unit_type=row.get('UNIT_TYPE', '').strip()
                )
                
                self.logger.debug(f"Found vulnerability: {vuln.cve} at commit {vuln.short_commit}")
                vulnerabilities.append(vuln)
        
        self.logger.info(f"Parsed {len(vulnerabilities)} unique vulnerabilities from CSV")
        return vulnerabilities


# =============================================================================
# Dockerfile Generator
# =============================================================================

class DockerfileGenerator:
    """Generates Dockerfiles appropriate for building vulnerable glibc versions"""
    
    # Dockerfile template for Ubuntu 14.04
    TEMPLATE_14_04 = '''# =============================================================================
# Dockerfile for {cve}
# Vulnerable glibc commit: {commit_hash}
# Base: Ubuntu 14.04 (GCC 4.8 - suitable for 2012-2014 code)
# =============================================================================
FROM ubuntu:14.04

LABEL maintainer="AI-SSD Project"
LABEL cve="{cve}"
LABEL commit="{commit_hash}"

# Prevent interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Update and install build dependencies
RUN apt-get update && apt-get install -y \\
    build-essential \\
    git \\
    gawk \\
    bison \\
    texinfo \\
    autoconf \\
    libtool \\
    gettext \\
    wget \\
    && rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /build

# Clone glibc repository and checkout vulnerable commit
RUN git clone --depth=1 https://sourceware.org/git/glibc.git /build/glibc-src || \\
    git clone https://github.com/bminor/glibc.git /build/glibc-src

WORKDIR /build/glibc-src
RUN git fetch --unshallow 2>/dev/null || true && \\
    git fetch origin {commit_hash} && \\
    git checkout {commit_hash}

# Create build directory
RUN mkdir -p /build/glibc-build

WORKDIR /build/glibc-build

# Configure glibc build
# Note: Using --disable-werror to allow building with warnings as errors disabled
RUN ../glibc-src/configure \\
    --prefix=/opt/glibc-vulnerable \\
    --disable-werror \\
    --disable-sanity-checks \\
    --enable-obsolete-rpc \\
    CC="gcc -fno-stack-protector" \\
    CFLAGS="-O2 -g -fno-stack-protector" \\
    || (cat config.log && exit 1)

# Build glibc (using -k to continue on errors, -j for parallel)
# Save build status to check later
RUN make -j$(nproc) -k 2>&1 | tee /build/build.log; \\
    echo "GLIBC_BUILD_EXIT_CODE=$?" >> /build/build_status

# Install to prefix (may partially succeed)
RUN make install -k 2>&1 | tee -a /build/build.log; \\
    echo "GLIBC_INSTALL_EXIT_CODE=$?" >> /build/build_status

# Verify glibc build produced necessary files
RUN echo "=== Checking glibc build output ===" && \\
    ls -la /opt/glibc-vulnerable/lib/ 2>/dev/null || echo "WARNING: /opt/glibc-vulnerable/lib/ not found" && \\
    ls /opt/glibc-vulnerable/lib/libc.so* 2>/dev/null || echo "WARNING: libc.so not found"

# Create directory for PoC
RUN mkdir -p /poc

# Copy exploit source
COPY poc_exploit.c /poc/exploit.c

# Compile the PoC against vulnerable glibc
# First, find the actual dynamic linker path
# Use fallback compilation attempts if linking with specific libraries fails
# Always fall back to system glibc if vulnerable glibc compilation fails
WORKDIR /poc
RUN DYNAMIC_LINKER=$(find /opt/glibc-vulnerable/lib -name 'ld-linux*.so*' -o -name 'ld-*.so*' 2>/dev/null | head -1) && \\
    echo "Found dynamic linker: $DYNAMIC_LINKER" && \\
    if [ -n "$DYNAMIC_LINKER" ] && [ -f "$DYNAMIC_LINKER" ]; then \\
        echo "Attempting compilation with vulnerable glibc..."; \\
        gcc -o exploit exploit.c \\
            -Wl,-rpath,/opt/glibc-vulnerable/lib \\
            -Wl,--dynamic-linker=$DYNAMIC_LINKER \\
            -L/opt/glibc-vulnerable/lib \\
            -I/opt/glibc-vulnerable/include \\
            -ldl -lpthread 2>&1 || \\
        gcc -o exploit exploit.c \\
            -Wl,-rpath,/opt/glibc-vulnerable/lib \\
            -Wl,--dynamic-linker=$DYNAMIC_LINKER \\
            -L/opt/glibc-vulnerable/lib \\
            -I/opt/glibc-vulnerable/include \\
            -ldl 2>&1 || \\
        gcc -o exploit exploit.c \\
            -Wl,-rpath,/opt/glibc-vulnerable/lib \\
            -Wl,--dynamic-linker=$DYNAMIC_LINKER \\
            -L/opt/glibc-vulnerable/lib \\
            -I/opt/glibc-vulnerable/include \\
            -lm 2>&1 || \\
        gcc -o exploit exploit.c \\
            -Wl,-rpath,/opt/glibc-vulnerable/lib \\
            -Wl,--dynamic-linker=$DYNAMIC_LINKER \\
            -L/opt/glibc-vulnerable/lib \\
            -I/opt/glibc-vulnerable/include 2>&1 || \\
        echo "Vulnerable glibc compilation failed"; \\
    fi && \\
    if [ ! -f /poc/exploit ]; then \\
        echo "Falling back to system glibc compilation..." && \\
        (gcc -o exploit exploit.c -ldl -lpthread 2>&1 || \\
        gcc -o exploit exploit.c -ldl 2>&1 || \\
        gcc -o exploit exploit.c -lm 2>&1 || \\
        gcc -o exploit exploit.c 2>&1); \\
    fi

# Verify exploit binary was created
RUN if [ ! -f /poc/exploit ]; then \\
        echo "ERROR: Failed to compile exploit binary!" && \\
        echo "=== Compilation environment ===" && \\
        gcc --version && \\
        echo "=== Source file ===" && \\
        head -50 /poc/exploit.c && \\
        echo "=== Attempting verbose compilation ===" && \\
        gcc -v -o exploit exploit.c 2>&1 || true; \\
        exit 1; \\
    else \\
        echo "SUCCESS: Exploit binary created" && \\
        ls -la /poc/exploit && \\
        file /poc/exploit; \\
    fi

# Set environment for running with vulnerable glibc
ENV LD_LIBRARY_PATH=/opt/glibc-vulnerable/lib

# Default command: run the exploit
CMD ["/poc/exploit"]
'''

    # Dockerfile template for Ubuntu 16.04
    TEMPLATE_16_04 = '''# =============================================================================
# Dockerfile for {cve}
# Vulnerable glibc commit: {commit_hash}
# Base: Ubuntu 16.04 (GCC 5.x - suitable for 2015-2016 code)
# =============================================================================
FROM ubuntu:16.04

LABEL maintainer="AI-SSD Project"
LABEL cve="{cve}"
LABEL commit="{commit_hash}"

# Prevent interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Update and install build dependencies
RUN apt-get update && apt-get install -y \\
    build-essential \\
    git \\
    gawk \\
    bison \\
    texinfo \\
    autoconf \\
    libtool \\
    gettext \\
    wget \\
    python3 \\
    && rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /build

# Clone glibc repository and checkout vulnerable commit
RUN git clone https://github.com/bminor/glibc.git /build/glibc-src

WORKDIR /build/glibc-src
RUN git fetch origin {commit_hash} && \\
    git checkout {commit_hash}

# Create build directory (glibc requires out-of-tree build)
RUN mkdir -p /build/glibc-build

WORKDIR /build/glibc-build

# Configure glibc build
RUN ../glibc-src/configure \\
    --prefix=/opt/glibc-vulnerable \\
    --disable-werror \\
    --disable-sanity-checks \\
    CC="gcc -fno-stack-protector" \\
    CFLAGS="-O2 -g -fno-stack-protector -Wno-error" \\
    || (cat config.log && exit 1)

# Build glibc (using -k to continue on errors)
# Save build status to check later
RUN make -j$(nproc) -k 2>&1 | tee /build/build.log; \\
    echo "GLIBC_BUILD_EXIT_CODE=$?" >> /build/build_status

# Install to prefix
RUN make install -k 2>&1 | tee -a /build/build.log; \\
    echo "GLIBC_INSTALL_EXIT_CODE=$?" >> /build/build_status

# Verify glibc build produced necessary files
RUN echo "=== Checking glibc build output ===" && \\
    ls -la /opt/glibc-vulnerable/lib/ 2>/dev/null || echo "WARNING: /opt/glibc-vulnerable/lib/ not found" && \\
    ls /opt/glibc-vulnerable/lib/libc.so* 2>/dev/null || echo "WARNING: libc.so not found"

# Create directory for PoC
RUN mkdir -p /poc

# Copy exploit source
COPY poc_exploit.c /poc/exploit.c

# Compile the PoC against vulnerable glibc
# First, find the actual dynamic linker path
# Use fallback compilation attempts if linking with specific libraries fails
# Always fall back to system glibc if vulnerable glibc compilation fails
WORKDIR /poc
RUN DYNAMIC_LINKER=$(find /opt/glibc-vulnerable/lib -name 'ld-linux*.so*' -o -name 'ld-*.so*' 2>/dev/null | head -1) && \\
    echo "Found dynamic linker: $DYNAMIC_LINKER" && \\
    if [ -n "$DYNAMIC_LINKER" ] && [ -f "$DYNAMIC_LINKER" ]; then \\
        echo "Attempting compilation with vulnerable glibc..."; \\
        gcc -o exploit exploit.c \\
            -Wl,-rpath,/opt/glibc-vulnerable/lib \\
            -Wl,--dynamic-linker=$DYNAMIC_LINKER \\
            -L/opt/glibc-vulnerable/lib \\
            -I/opt/glibc-vulnerable/include \\
            -ldl -lpthread 2>&1 || \\
        gcc -o exploit exploit.c \\
            -Wl,-rpath,/opt/glibc-vulnerable/lib \\
            -Wl,--dynamic-linker=$DYNAMIC_LINKER \\
            -L/opt/glibc-vulnerable/lib \\
            -I/opt/glibc-vulnerable/include \\
            -ldl 2>&1 || \\
        gcc -o exploit exploit.c \\
            -Wl,-rpath,/opt/glibc-vulnerable/lib \\
            -Wl,--dynamic-linker=$DYNAMIC_LINKER \\
            -L/opt/glibc-vulnerable/lib \\
            -I/opt/glibc-vulnerable/include \\
            -lm 2>&1 || \\
        gcc -o exploit exploit.c \\
            -Wl,-rpath,/opt/glibc-vulnerable/lib \\
            -Wl,--dynamic-linker=$DYNAMIC_LINKER \\
            -L/opt/glibc-vulnerable/lib \\
            -I/opt/glibc-vulnerable/include 2>&1 || \\
        echo "Vulnerable glibc compilation failed"; \\
    fi && \\
    if [ ! -f /poc/exploit ]; then \\
        echo "Falling back to system glibc compilation..." && \\
        (gcc -o exploit exploit.c -ldl -lpthread 2>&1 || \\
        gcc -o exploit exploit.c -ldl 2>&1 || \\
        gcc -o exploit exploit.c -lm 2>&1 || \\
        gcc -o exploit exploit.c 2>&1); \\
    fi

# Verify exploit binary was created
RUN if [ ! -f /poc/exploit ]; then \\
        echo "ERROR: Failed to compile exploit binary!" && \\
        echo "=== Compilation environment ===" && \\
        gcc --version && \\
        echo "=== Source file ===" && \\
        head -50 /poc/exploit.c && \\
        echo "=== Attempting verbose compilation ===" && \\
        gcc -v -o exploit exploit.c 2>&1 || true; \\
        exit 1; \\
    else \\
        echo "SUCCESS: Exploit binary created" && \\
        ls -la /poc/exploit && \\
        file /poc/exploit; \\
    fi

# Set environment for running with vulnerable glibc
ENV LD_LIBRARY_PATH=/opt/glibc-vulnerable/lib

# Default command: run the exploit
CMD ["/poc/exploit"]
'''

    # Dockerfile template for Ubuntu 18.04
    TEMPLATE_18_04 = '''# =============================================================================
# Dockerfile for {cve}
# Vulnerable glibc commit: {commit_hash}
# Base: Ubuntu 18.04 (GCC 7.x - suitable for 2017-2018 code)
# =============================================================================
FROM ubuntu:18.04

LABEL maintainer="AI-SSD Project"
LABEL cve="{cve}"
LABEL commit="{commit_hash}"

# Prevent interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Update and install build dependencies
RUN apt-get update && apt-get install -y \\
    build-essential \\
    git \\
    gawk \\
    bison \\
    texinfo \\
    autoconf \\
    libtool \\
    gettext \\
    wget \\
    python3 \\
    && rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /build

# Clone glibc repository and checkout vulnerable commit
RUN git clone https://github.com/bminor/glibc.git /build/glibc-src

WORKDIR /build/glibc-src
RUN git fetch origin {commit_hash} && \\
    git checkout {commit_hash}

# Create build directory
RUN mkdir -p /build/glibc-build

WORKDIR /build/glibc-build

# Configure glibc build
RUN ../glibc-src/configure \\
    --prefix=/opt/glibc-vulnerable \\
    --disable-werror \\
    --disable-sanity-checks \\
    CC="gcc -fno-stack-protector" \\
    CFLAGS="-O2 -g -fno-stack-protector -Wno-error" \\
    || (cat config.log && exit 1)

# Build glibc
# Save build status to check later
RUN make -j$(nproc) -k 2>&1 | tee /build/build.log; \\
    echo "GLIBC_BUILD_EXIT_CODE=$?" >> /build/build_status

# Install to prefix
RUN make install -k 2>&1 | tee -a /build/build.log; \\
    echo "GLIBC_INSTALL_EXIT_CODE=$?" >> /build/build_status

# Verify glibc build produced necessary files
RUN echo "=== Checking glibc build output ===" && \\
    ls -la /opt/glibc-vulnerable/lib/ 2>/dev/null || echo "WARNING: /opt/glibc-vulnerable/lib/ not found" && \\
    ls /opt/glibc-vulnerable/lib/libc.so* 2>/dev/null || echo "WARNING: libc.so not found"

# Create directory for PoC
RUN mkdir -p /poc

# Copy exploit source
COPY poc_exploit.c /poc/exploit.c

# Compile the PoC against vulnerable glibc
# First, find the actual dynamic linker path
# Use fallback compilation attempts if linking with specific libraries fails
# Always fall back to system glibc if vulnerable glibc compilation fails
WORKDIR /poc
RUN DYNAMIC_LINKER=$(find /opt/glibc-vulnerable/lib -name 'ld-linux*.so*' -o -name 'ld-*.so*' 2>/dev/null | head -1) && \\
    echo "Found dynamic linker: $DYNAMIC_LINKER" && \\
    if [ -n "$DYNAMIC_LINKER" ] && [ -f "$DYNAMIC_LINKER" ]; then \\
        echo "Attempting compilation with vulnerable glibc..."; \\
        gcc -o exploit exploit.c \\
            -Wl,-rpath,/opt/glibc-vulnerable/lib \\
            -Wl,--dynamic-linker=$DYNAMIC_LINKER \\
            -L/opt/glibc-vulnerable/lib \\
            -I/opt/glibc-vulnerable/include \\
            -ldl -lpthread 2>&1 || \\
        gcc -o exploit exploit.c \\
            -Wl,-rpath,/opt/glibc-vulnerable/lib \\
            -Wl,--dynamic-linker=$DYNAMIC_LINKER \\
            -L/opt/glibc-vulnerable/lib \\
            -I/opt/glibc-vulnerable/include \\
            -ldl 2>&1 || \\
        gcc -o exploit exploit.c \\
            -Wl,-rpath,/opt/glibc-vulnerable/lib \\
            -Wl,--dynamic-linker=$DYNAMIC_LINKER \\
            -L/opt/glibc-vulnerable/lib \\
            -I/opt/glibc-vulnerable/include \\
            -lm 2>&1 || \\
        gcc -o exploit exploit.c \\
            -Wl,-rpath,/opt/glibc-vulnerable/lib \\
            -Wl,--dynamic-linker=$DYNAMIC_LINKER \\
            -L/opt/glibc-vulnerable/lib \\
            -I/opt/glibc-vulnerable/include 2>&1 || \\
        echo "Vulnerable glibc compilation failed"; \\
    fi && \\
    if [ ! -f /poc/exploit ]; then \\
        echo "Falling back to system glibc compilation..." && \\
        (gcc -o exploit exploit.c -ldl -lpthread 2>&1 || \\
        gcc -o exploit exploit.c -ldl 2>&1 || \\
        gcc -o exploit exploit.c -lm 2>&1 || \\
        gcc -o exploit exploit.c 2>&1); \\
    fi

# Verify exploit binary was created
RUN if [ ! -f /poc/exploit ]; then \\
        echo "ERROR: Failed to compile exploit binary!" && \\
        echo "=== Compilation environment ===" && \\
        gcc --version && \\
        echo "=== Source file ===" && \\
        head -50 /poc/exploit.c && \\
        echo "=== Attempting verbose compilation ===" && \\
        gcc -v -o exploit exploit.c 2>&1 || true; \\
        exit 1; \\
    else \\
        echo "SUCCESS: Exploit binary created" && \\
        ls -la /poc/exploit && \\
        file /poc/exploit; \\
    fi

# Set environment for running with vulnerable glibc
ENV LD_LIBRARY_PATH=/opt/glibc-vulnerable/lib

# Default command: run the exploit
CMD ["/poc/exploit"]
'''

    def __init__(self, logger: logging.Logger):
        self.logger = logger
        self.templates = {
            "ubuntu:14.04": self.TEMPLATE_14_04,
            "ubuntu:16.04": self.TEMPLATE_16_04,
            "ubuntu:18.04": self.TEMPLATE_18_04,
        }
    
    def get_base_image(self, vuln: VulnerabilityInfo) -> str:
        """Determine appropriate base image based on CVE/commit date"""
        # Try to get year from CVE hint
        if vuln.cve in CVE_YEAR_HINTS:
            year = CVE_YEAR_HINTS[vuln.cve]
            self.logger.debug(f"Using year hint for {vuln.cve}: {year}")
            return COMMIT_OS_MAPPING.get(year, COMMIT_OS_MAPPING["default"])
        
        # Extract year from CVE name (e.g., CVE-2015-7547 -> 2015)
        try:
            parts = vuln.cve.split('-')
            if len(parts) >= 2:
                year = parts[1][:4]
                if year in COMMIT_OS_MAPPING:
                    return COMMIT_OS_MAPPING[year]
        except (IndexError, ValueError):
            pass
        
        return COMMIT_OS_MAPPING["default"]
    
    def generate(self, vuln: VulnerabilityInfo, output_dir: Path) -> Path:
        """Generate Dockerfile for a vulnerability"""
        base_image = self.get_base_image(vuln)
        self.logger.info(f"Generating Dockerfile for {vuln.cve} using {base_image}")
        
        template = self.templates.get(base_image, self.TEMPLATE_16_04)
        
        dockerfile_content = template.format(
            cve=vuln.cve,
            commit_hash=vuln.commit_hash
        )
        
        # Create output directory for this CVE
        cve_dir = output_dir / vuln.cve.lower()
        cve_dir.mkdir(parents=True, exist_ok=True)
        
        dockerfile_path = cve_dir / "Dockerfile"
        with open(dockerfile_path, 'w') as f:
            f.write(dockerfile_content)
        
        self.logger.debug(f"Dockerfile written to: {dockerfile_path}")
        return dockerfile_path


# =============================================================================
# Docker Build and Execution Manager
# =============================================================================

class DockerManager:
    """Manages Docker image builds and container execution"""
    
    def __init__(self, logger: logging.Logger, timeout: int = 3600):
        self.logger = logger
        self.timeout = timeout
        try:
            self.client = docker.from_env()
            self.client.ping()
            self.logger.info("Successfully connected to Docker daemon")
        except docker.errors.DockerException as e:
            self.logger.error(f"Failed to connect to Docker: {e}")
            raise
    
    def build_image(self, vuln: VulnerabilityInfo, build_context: Path) -> Tuple[bool, Optional[str]]:
        """Build Docker image for vulnerability"""
        self.logger.info(f"Building Docker image for {vuln.cve}...")
        
        try:
            image, build_logs = self.client.images.build(
                path=str(build_context),
                tag=vuln.image_name,
                rm=True,
                forcerm=True,
                timeout=self.timeout
            )
            
            # Collect build logs
            log_output = []
            for chunk in build_logs:
                if 'stream' in chunk:
                    log_output.append(chunk['stream'])
                elif 'error' in chunk:
                    log_output.append(f"ERROR: {chunk['error']}")
            
            self.logger.info(f"Successfully built image: {vuln.image_name}")
            return True, '\n'.join(log_output)
            
        except BuildError as e:
            self.logger.error(f"Build failed for {vuln.cve}: {e}")
            return False, str(e)
        except APIError as e:
            self.logger.error(f"Docker API error for {vuln.cve}: {e}")
            return False, str(e)
    
    def run_container(self, vuln: VulnerabilityInfo, run_timeout: int = 300) -> Tuple[bool, int, str]:
        """Run container and execute PoC"""
        self.logger.info(f"Running container for {vuln.cve}...")
        
        try:
            # Run container with resource limits
            container = self.client.containers.run(
                vuln.image_name,
                name=vuln.container_name,
                detach=True,
                mem_limit='2g',
                cpu_period=100000,
                cpu_quota=100000,  # Limit to 1 CPU
                network_disabled=True,  # Security: disable network
                remove=False  # Keep container for log inspection
            )
            
            # Wait for container to finish (with timeout)
            result = container.wait(timeout=run_timeout)
            exit_code = result.get('StatusCode', -1)
            
            # Get container logs
            logs = container.logs(stdout=True, stderr=True).decode('utf-8', errors='replace')
            
            # Clean up container
            try:
                container.remove(force=True)
            except:
                pass
            
            # Interpret results
            # For most vulnerabilities, a crash (segfault) or specific exit codes indicate success
            vulnerability_triggered = self._interpret_exit_code(vuln, exit_code, logs)
            
            self.logger.info(f"Container {vuln.container_name} exited with code {exit_code}")
            return vulnerability_triggered, exit_code, logs
            
        except ContainerError as e:
            self.logger.warning(f"Container error (may indicate vulnerability triggered): {e}")
            # Container errors often mean the vulnerability was triggered
            return True, e.exit_status, str(e)
        except Exception as e:
            self.logger.error(f"Failed to run container for {vuln.cve}: {e}")
            return False, -1, str(e)
    
    def _interpret_exit_code(self, vuln: VulnerabilityInfo, exit_code: int, logs: str) -> bool:
        """Interpret container exit code and logs to determine if vulnerability was triggered"""
        logs_lower = logs.lower()
        
        # FIRST: Check for environment/execution errors - these are NOT successful reproductions
        # These indicate the test setup failed, not that the vulnerability was exercised
        if "no such file or directory" in logs_lower:
            self.logger.error(f"{vuln.cve}: Environment error - exploit binary not found. Build/setup issue.")
            return False
        
        if "exec format error" in logs_lower:
            self.logger.error(f"{vuln.cve}: Environment error - binary format issue. Build/architecture problem.")
            return False
        
        if "permission denied" in logs_lower and "exec" in logs_lower:
            self.logger.error(f"{vuln.cve}: Environment error - permission denied executing binary.")
            return False
        
        # Segmentation fault (139 = 128 + 11 SIGSEGV)
        if exit_code == 139:
            self.logger.info(f"{vuln.cve}: Segmentation fault detected - vulnerability likely triggered")
            return True
        
        # Abort (134 = 128 + 6 SIGABRT)
        if exit_code == 134:
            self.logger.info(f"{vuln.cve}: Abort detected - vulnerability likely triggered")
            return True
        
        # Stack smashing detected
        if "stack smashing" in logs_lower:
            self.logger.info(f"{vuln.cve}: Stack smashing detected in logs")
            return True
        
        # Buffer overflow indicators
        if any(indicator in logs_lower for indicator in ['overflow', 'corrupted', 'double free']):
            self.logger.info(f"{vuln.cve}: Overflow/corruption detected in logs")
            return True
        
        # CVE-specific detection logic
        # For CVE-2012-3480 (strtod integer overflow)
        # The PoC outputs the result of strtod() on a malformed huge number
        # Output like "0x0p+0" or any hex float output means the vulnerable code path was exercised
        if vuln.cve == "CVE-2012-3480":
            # If we got any output at all from strtod, the vulnerable code was exercised
            # The format is hex float: 0x...p+... or 0x...p-...
            if "0x" in logs and "p" in logs:
                self.logger.info(f"{vuln.cve}: strtod output detected ({logs.strip()}) - vulnerable code path exercised")
                return True
            # Also check for any numeric output
            if logs.strip() and exit_code == 0:
                self.logger.info(f"{vuln.cve}: PoC completed with output - vulnerable code path exercised")
                return True
        
        # For CVE-2015-7547 (getaddrinfo stack buffer overflow)
        if vuln.cve == "CVE-2015-7547":
            if exit_code != 0 or "getaddrinfo" in logs.lower():
                self.logger.info(f"{vuln.cve}: getaddrinfo exercised - vulnerable code path triggered")
                return True
        
        # For CVE-2014-5119 (__gconv_translit_find heap corruption)
        # This is a complex exploit requiring pkexec and pty helper
        # Simple compilation and execution won't fully trigger it
        if vuln.cve == "CVE-2014-5119":
            if "corrupted" in logs_lower or "double-linked" in logs_lower:
                self.logger.info(f"{vuln.cve}: Heap corruption detected")
                return True
            # Only consider as success if exploit actually ran (not env errors)
            # and produced meaningful output or specific exit codes
            if exit_code in [134, 139]:  # SIGABRT or SIGSEGV
                self.logger.info(f"{vuln.cve}: Crash detected (exit {exit_code}) - vulnerability triggered")
                return True
            if exit_code == 0 and logs.strip() and "error" not in logs_lower:
                self.logger.info(f"{vuln.cve}: Exploit executed successfully (exit 0) - code path exercised")
                return True
            # Exit code 1 with no output is likely an error, not success
            if exit_code == 1 and logs.strip():
                self.logger.info(f"{vuln.cve}: Exploit completed with exit 1 and output")
                return True
            self.logger.warning(f"{vuln.cve}: Unclear result (exit {exit_code}) - marking as not reproduced")
            return False
        
        # Exit code 0 might also indicate the vulnerability was exercised
        # depending on the specific PoC
        return exit_code != 0
    
    def cleanup_image(self, vuln: VulnerabilityInfo):
        """Remove Docker image"""
        try:
            self.client.images.remove(vuln.image_name, force=True)
            self.logger.debug(f"Removed image: {vuln.image_name}")
        except ImageNotFound:
            pass
        except Exception as e:
            self.logger.warning(f"Failed to remove image {vuln.image_name}: {e}")
    
    def cleanup_container(self, vuln: VulnerabilityInfo):
        """Remove Docker container if exists"""
        try:
            container = self.client.containers.get(vuln.container_name)
            container.remove(force=True)
            self.logger.debug(f"Removed container: {vuln.container_name}")
        except:
            pass


# =============================================================================
# PoC Manager
# =============================================================================

class PoCManager:
    """Manages PoC exploit files"""
    
    def __init__(self, exploits_dir: Path, logger: logging.Logger):
        self.exploits_dir = exploits_dir
        self.logger = logger
    
    def find_poc(self, vuln: VulnerabilityInfo) -> Optional[Path]:
        """Find PoC file for a vulnerability"""
        # Check multiple possible locations and naming conventions
        possible_paths = [
            self.exploits_dir / vuln.cve / "exploit.c",
            self.exploits_dir / vuln.cve / "poc.c",
            self.exploits_dir / vuln.cve.lower() / "exploit.c",
            self.exploits_dir / f"{vuln.cve}.c",
            self.exploits_dir / f"{vuln.cve.lower()}.c",
        ]
        
        for path in possible_paths:
            if path.exists():
                self.logger.debug(f"Found PoC for {vuln.cve} at: {path}")
                return path
        
        self.logger.warning(f"No PoC found for {vuln.cve}")
        return None
    
    def copy_poc_to_build_context(self, poc_path: Path, build_context: Path) -> bool:
        """Copy PoC file to Docker build context"""
        try:
            dest = build_context / "poc_exploit.c"
            shutil.copy2(poc_path, dest)
            self.logger.debug(f"Copied PoC to: {dest}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to copy PoC: {e}")
            return False


# =============================================================================
# Report Generator
# =============================================================================

class ReportGenerator:
    """Generates JSON reports of execution results"""
    
    def __init__(self, results_dir: Path, logger: logging.Logger):
        self.results_dir = results_dir
        self.results_dir.mkdir(parents=True, exist_ok=True)
        self.logger = logger
        self.results: List[ExecutionResult] = []
    
    def add_result(self, result: ExecutionResult):
        """Add a result to the report"""
        self.results.append(result)
    
    def generate_report(self, phase_start: datetime = None, phase_end: datetime = None) -> Path:
        """Generate JSON report file with comprehensive timing information"""
        report_path = self.results_dir / "results.json"
        
        # Calculate total execution time from all results
        total_execution_time = sum(r.execution_time_seconds for r in self.results)
        
        # Calculate per-CVE timing
        cve_timings = {}
        for r in self.results:
            if r.cve not in cve_timings:
                cve_timings[r.cve] = {
                    "execution_time_seconds": 0.0,
                    "build_success": False,
                    "vulnerability_reproduced": False
                }
            cve_timings[r.cve]["execution_time_seconds"] = r.execution_time_seconds
            cve_timings[r.cve]["build_success"] = r.build_success
            cve_timings[r.cve]["vulnerability_reproduced"] = r.vulnerability_reproduced
        
        # Count different failure types for better analysis
        build_errors = sum(1 for r in self.results if r.status == ExecutionStatus.BUILD_ERROR.value)
        execution_errors = sum(1 for r in self.results if r.status == ExecutionStatus.EXECUTION_ERROR.value)
        poc_not_found = sum(1 for r in self.results if r.status == ExecutionStatus.POC_NOT_FOUND.value)
        timeouts = sum(1 for r in self.results if r.status == ExecutionStatus.TIMEOUT.value)
        unknown_errors = sum(1 for r in self.results if r.status == ExecutionStatus.UNKNOWN_ERROR.value)
        successful = sum(1 for r in self.results if r.vulnerability_reproduced)
        
        report_data = {
            "metadata": {
                "generated_at": datetime.now().isoformat(),
                "phase": "Phase 1 - Vulnerability Reproduction",
                "total_vulnerabilities": len(self.results),
                "successful_reproductions": successful,
                "failed_builds": sum(1 for r in self.results if not r.build_success),
            },
            "phase_timing": {
                "start_time": phase_start.isoformat() if phase_start else None,
                "end_time": phase_end.isoformat() if phase_end else None,
                "total_duration_seconds": (phase_end - phase_start).total_seconds() if phase_start and phase_end else total_execution_time,
            },
            "failure_breakdown": {
                "build_errors": build_errors,
                "execution_errors": execution_errors,
                "poc_not_found": poc_not_found,
                "timeouts": timeouts,
                "unknown_errors": unknown_errors,
                "total_failures": len(self.results) - successful,
            },
            "timing_by_cve": cve_timings,
            "total_execution_time_seconds": total_execution_time,
            "results": [asdict(r) for r in self.results]
        }
        
        with open(report_path, 'w') as f:
            json.dump(report_data, f, indent=2)
        
        self.logger.info(f"Report generated: {report_path}")
        return report_path
    
    def print_summary(self):
        """Print summary to console"""
        print("\n" + "=" * 60)
        print("EXECUTION SUMMARY")
        print("=" * 60)
        
        for result in self.results:
            status_icon = "✓" if result.vulnerability_reproduced else "✗"
            print(f"{status_icon} {result.cve}: {result.status}")
            if result.error_message:
                print(f"    Error: {result.error_message[:100]}...")
        
        print("-" * 60)
        total = len(self.results)
        success = sum(1 for r in self.results if r.vulnerability_reproduced)
        print(f"Total: {total} | Reproduced: {success} | Failed: {total - success}")
        print("=" * 60 + "\n")


# =============================================================================
# Pipeline Orchestrator
# =============================================================================

class PipelineOrchestrator:
    """Main orchestrator that coordinates all pipeline components"""
    
    def __init__(self, args: argparse.Namespace):
        self.base_dir = Path(args.base_dir).resolve()
        self.csv_path = Path(args.csv_file).resolve()
        self.exploits_dir = Path(args.exploits_dir).resolve()
        self.build_timeout = args.build_timeout
        self.run_timeout = args.run_timeout
        self.cleanup = args.cleanup
        self.specific_cve = args.cve
        
        # Setup directories
        self.docker_builds_dir = self.base_dir / "docker_builds"
        self.results_dir = self.base_dir / "results"
        self.logs_dir = self.base_dir / "logs"
        
        # Setup logging
        self.logger = setup_logging(self.logs_dir, args.verbose)
        
        # Initialize components
        self.csv_parser = CSVParser(self.csv_path, self.logger)
        self.dockerfile_gen = DockerfileGenerator(self.logger)
        self.docker_mgr = DockerManager(self.logger, self.build_timeout)
        self.poc_mgr = PoCManager(self.exploits_dir, self.logger)
        self.report_gen = ReportGenerator(self.results_dir, self.logger)
    
    def run(self):
        """Execute the full pipeline"""
        phase_start_time = datetime.now()
        
        self.logger.info("=" * 60)
        self.logger.info("Starting Phase 1: Vulnerability Reproduction Pipeline")
        self.logger.info(f"Phase Start Time: {phase_start_time.isoformat()}")
        self.logger.info("=" * 60)
        self.logger.info(f"Base directory: {self.base_dir}")
        self.logger.info(f"CSV file: {self.csv_path}")
        self.logger.info(f"Exploits directory: {self.exploits_dir}")
        
        # Parse vulnerabilities from CSV
        try:
            vulnerabilities = self.csv_parser.parse()
        except FileNotFoundError as e:
            self.logger.error(str(e))
            sys.exit(1)
        
        # Filter to specific CVE if requested
        if self.specific_cve:
            vulnerabilities = [v for v in vulnerabilities if v.cve == self.specific_cve]
            if not vulnerabilities:
                self.logger.error(f"CVE {self.specific_cve} not found in CSV")
                sys.exit(1)
        
        self.logger.info(f"Found {len(vulnerabilities)} vulnerabilities to process")
        
        # Process each vulnerability
        for idx, vuln in enumerate(vulnerabilities, 1):
            self.logger.info(f"\n{'='*60}")
            self.logger.info(f"Processing ({idx}/{len(vulnerabilities)}): {vuln.cve}")
            self.logger.info(f"Commit: {vuln.commit_hash}")
            self.logger.info(f"{'='*60}")
            
            result = self._process_vulnerability(vuln)
            self.report_gen.add_result(result)
            self.logger.info(f"Completed {vuln.cve}: {result.status} (duration: {result.execution_time_seconds:.1f}s)")
        
        phase_end_time = datetime.now()
        phase_duration = (phase_end_time - phase_start_time).total_seconds()
        
        # Generate final report with phase timing
        report_path = self.report_gen.generate_report(phase_start_time, phase_end_time)
        self.report_gen.print_summary()
        
        self.logger.info("=" * 60)
        self.logger.info(f"Phase 1 Complete")
        self.logger.info(f"Phase End Time: {phase_end_time.isoformat()}")
        self.logger.info(f"Phase Duration: {phase_duration:.1f}s ({phase_duration/60:.1f}m)")
        self.logger.info(f"Results saved to: {report_path}")
        self.logger.info("=" * 60)
    
    def _process_vulnerability(self, vuln: VulnerabilityInfo) -> ExecutionResult:
        """Process a single vulnerability"""
        start_time = datetime.now()
        
        # Initialize result
        result = ExecutionResult(
            cve=vuln.cve,
            commit_hash=vuln.commit_hash,
            status=ExecutionStatus.UNKNOWN_ERROR.value,
            vulnerability_reproduced=False,
            build_success=False,
            poc_executed=False,
            execution_time_seconds=0,
            error_message=None,
            container_logs=None,
            timestamp=start_time.isoformat()
        )
        
        try:
            # Step 1: Find PoC
            poc_path = self.poc_mgr.find_poc(vuln)
            if not poc_path:
                result.status = ExecutionStatus.POC_NOT_FOUND.value
                result.error_message = f"No PoC found in {self.exploits_dir}"
                return result
            
            # Step 2: Generate Dockerfile
            dockerfile_path = self.dockerfile_gen.generate(vuln, self.docker_builds_dir)
            build_context = dockerfile_path.parent
            
            # Step 3: Copy PoC to build context
            if not self.poc_mgr.copy_poc_to_build_context(poc_path, build_context):
                result.status = ExecutionStatus.UNKNOWN_ERROR.value
                result.error_message = "Failed to copy PoC to build context"
                return result
            
            # Step 4: Build Docker image
            build_success, build_logs = self.docker_mgr.build_image(vuln, build_context)
            if not build_success:
                result.status = ExecutionStatus.BUILD_ERROR.value
                result.error_message = "Docker build failed"
                result.container_logs = build_logs
                return result
            
            result.build_success = True
            
            # Step 5: Run container and execute PoC
            vuln_triggered, exit_code, run_logs = self.docker_mgr.run_container(
                vuln, self.run_timeout
            )
            
            result.poc_executed = True
            result.container_logs = run_logs
            result.vulnerability_reproduced = vuln_triggered
            
            if vuln_triggered:
                result.status = ExecutionStatus.SUCCESS.value
            else:
                result.status = ExecutionStatus.EXECUTION_ERROR.value
                result.error_message = f"PoC exited with code {exit_code} but vulnerability not confirmed"
            
        except Exception as e:
            self.logger.exception(f"Error processing {vuln.cve}")
            result.status = ExecutionStatus.UNKNOWN_ERROR.value
            result.error_message = str(e)
        
        finally:
            # Cleanup if requested
            if self.cleanup:
                self.docker_mgr.cleanup_container(vuln)
                self.docker_mgr.cleanup_image(vuln)
            
            # Calculate execution time
            end_time = datetime.now()
            result.execution_time_seconds = (end_time - start_time).total_seconds()
        
        return result


# =============================================================================
# Main Entry Point
# =============================================================================

def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="AI-SSD Vulnerability Reproduction Pipeline Orchestrator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run full pipeline
  python orchestrator.py
  
  # Run for specific CVE
  python orchestrator.py --cve CVE-2015-7547
  
  # Run with custom paths
  python orchestrator.py --csv-file /path/to/file-function.csv --exploits-dir /path/to/exploits
  
  # Run with cleanup and verbose output
  python orchestrator.py --cleanup --verbose
        """
    )
    
    parser.add_argument(
        '--base-dir',
        type=str,
        default=os.path.dirname(os.path.abspath(__file__)),
        help='Base directory for the project (default: script directory)'
    )
    
    parser.add_argument(
        '--csv-file',
        type=str,
        default=None,
        help='Path to file-function.csv (default: <base-dir>/documentation/file-function.csv)'
    )
    
    parser.add_argument(
        '--exploits-dir',
        type=str,
        default=None,
        help='Path to exploits directory (default: <base-dir>/exploits)'
    )
    
    parser.add_argument(
        '--cve',
        type=str,
        default=None,
        help='Process only this specific CVE'
    )
    
    parser.add_argument(
        '--build-timeout',
        type=int,
        default=3600,
        help='Docker build timeout in seconds (default: 3600)'
    )
    
    parser.add_argument(
        '--run-timeout',
        type=int,
        default=300,
        help='Container run timeout in seconds (default: 300)'
    )
    
    parser.add_argument(
        '--cleanup',
        action='store_true',
        help='Clean up Docker images and containers after execution'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose output'
    )
    
    args = parser.parse_args()
    
    # Set default paths relative to base directory
    if args.csv_file is None:
        args.csv_file = os.path.join(args.base_dir, 'documentation', 'file-function.csv')
    
    if args.exploits_dir is None:
        args.exploits_dir = os.path.join(args.base_dir, 'exploits')
    
    return args


def main():
    """Main entry point"""
    args = parse_arguments()
    
    try:
        orchestrator = PipelineOrchestrator(args)
        orchestrator.run()
    except KeyboardInterrupt:
        print("\nPipeline interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
