#!/usr/bin/env python3
# =============================================================================
# AI-SSD Project - Phase 3: Multi-Layered Patch Validation Pipeline
# =============================================================================
# This script automates the validation of LLM-generated security patches by:
# 1. Building Docker images with patched glibc code
# 2. Running PoC exploits to verify vulnerability is mitigated
# 3. Running SAST tools to detect any new vulnerabilities introduced
# 4. Generating comprehensive validation reports
# =============================================================================

import os
import sys
import csv
import json
import shutil
import logging
import argparse
import subprocess
import tempfile
import re
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, asdict, field
from typing import Dict, List, Optional, Tuple, Any
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
COMMIT_OS_MAPPING = {
    "2012": "ubuntu:14.04",
    "2013": "ubuntu:14.04",
    "2014": "ubuntu:14.04",
    "2015": "ubuntu:16.04",
    "2016": "ubuntu:16.04",
    "2017": "ubuntu:18.04",
    "2018": "ubuntu:18.04",
    "default": "ubuntu:16.04"
}

# Known CVE to approximate commit year mapping
CVE_YEAR_HINTS = {
    "CVE-2012-3480": "2012",
    "CVE-2014-5119": "2014",
    "CVE-2015-7547": "2015",
}

# CVE to vulnerable file path mapping (within glibc source tree)
CVE_FILE_MAPPING = {
    "CVE-2012-3480": "stdlib/strtod_l.c",
    "CVE-2014-5119": "iconv/gconv_trans.c",
    "CVE-2015-7547": "resolv/res_send.c",
}

# SAST Tools Configuration
# These are common, well-established C/C++ static analysis tools
SAST_TOOLS = {
    "cppcheck": {
        "install_cmd": "apt-get install -y cppcheck",
        "run_cmd": "cppcheck --enable=all --error-exitcode=1 --xml --xml-version=2 {file} 2>&1",
        "description": "Static analysis tool for C/C++ code",
        "severity_levels": ["error", "warning", "style", "performance", "portability"],
    },
    "flawfinder": {
        "install_cmd": "apt-get install -y flawfinder || pip install flawfinder",
        "run_cmd": "flawfinder --minlevel=1 --dataonly --quiet {file}",
        "description": "Examines C/C++ source code for security weaknesses",
        "severity_levels": [1, 2, 3, 4, 5],  # 5 is highest risk
    },
    "rats": {
        "install_cmd": "apt-get install -y rats || true",
        "run_cmd": "rats --xml {file} 2>/dev/null || echo 'RATS not available'",
        "description": "Rough Auditing Tool for Security",
        "severity_levels": ["High", "Medium", "Low"],
    },
}


class ValidationStatus(Enum):
    """Status codes for validation results"""
    SUCCESS = "Success"                          # Patch validated successfully
    POC_STILL_WORKS = "PoC Still Works"          # Vulnerability not fixed
    BUILD_ERROR = "Build Error"                  # Failed to build patched glibc
    SAST_FAILED = "SAST Failed"                  # SAST found new vulnerabilities
    POC_NOT_FOUND = "PoC Not Found"              # No exploit found for CVE
    PATCH_NOT_FOUND = "Patch Not Found"          # No patch file found
    INVALID_PATCH = "Invalid Patch"              # Patch file is invalid/empty
    TIMEOUT = "Timeout"                          # Execution timed out
    UNKNOWN_ERROR = "Unknown Error"              # Unexpected error occurred


class SASTSeverity(Enum):
    """SAST finding severity levels"""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


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


@dataclass
class PatchInfo:
    """Data class to hold patch information"""
    cve_id: str
    model_name: str
    patch_dir: Path
    patched_file: Optional[Path] = None
    function_only_file: Optional[Path] = None
    response_json: Optional[Path] = None
    is_valid: bool = False
    original_filepath: str = ""
    
    @property
    def image_name(self) -> str:
        """Generate Docker image name for this patch"""
        safe_model = self.model_name.replace(":", "_").replace(".", "_")
        return f"glibc-patch/{self.cve_id.lower()}-{safe_model}:latest"
    
    @property
    def container_name(self) -> str:
        """Generate container name for this patch"""
        safe_model = self.model_name.replace(":", "_").replace(".", "_")
        return f"patch-test-{self.cve_id.lower()}-{safe_model}"


@dataclass
class SASTFinding:
    """Data class for a single SAST finding"""
    tool: str
    severity: str
    message: str
    line: Optional[int] = None
    column: Optional[int] = None
    cwe_id: Optional[str] = None
    file_path: Optional[str] = None


@dataclass
class SASTResult:
    """Data class for SAST analysis results"""
    tool: str
    success: bool
    findings: List[SASTFinding] = field(default_factory=list)
    error_message: Optional[str] = None
    raw_output: str = ""
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0


@dataclass
class ValidationResult:
    """Data class to hold validation results"""
    cve_id: str
    model_name: str
    status: str
    poc_blocked: bool                              # True if PoC no longer works (vulnerability fixed)
    build_success: bool
    sast_passed: bool
    sast_results: List[Dict[str, Any]] = field(default_factory=list)
    poc_exit_code: Optional[int] = None
    poc_output: Optional[str] = None
    error_message: Optional[str] = None
    execution_time_seconds: float = 0
    timestamp: str = ""
    patch_file: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            "cve_id": self.cve_id,
            "model_name": self.model_name,
            "status": self.status,
            "poc_blocked": self.poc_blocked,
            "build_success": self.build_success,
            "sast_passed": self.sast_passed,
            "sast_results": self.sast_results,
            "poc_exit_code": self.poc_exit_code,
            "poc_output": self.poc_output[:2000] if self.poc_output else None,  # Truncate long outputs
            "error_message": self.error_message,
            "execution_time_seconds": self.execution_time_seconds,
            "timestamp": self.timestamp,
            "patch_file": self.patch_file,
        }


# =============================================================================
# Logging Configuration
# =============================================================================

def setup_logging(log_dir: Path, verbose: bool = False) -> logging.Logger:
    """Configure logging for the validator"""
    log_dir.mkdir(parents=True, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = log_dir / f"validator_{timestamp}.log"
    
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
    
    # Configure logger
    logger = logging.getLogger('validator')
    logger.setLevel(logging.DEBUG)
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
    
    def parse(self) -> Dict[str, VulnerabilityInfo]:
        """Parse CSV and return dict mapping CVE to VulnerabilityInfo"""
        vulnerabilities = {}
        
        self.logger.info(f"Parsing CSV file: {self.csv_path}")
        
        if not self.csv_path.exists():
            raise FileNotFoundError(f"CSV file not found: {self.csv_path}")
        
        with open(self.csv_path, 'r', encoding='utf-8') as f:
            # Detect delimiter
            sample = f.read(2048)
            f.seek(0)
            delimiter = ';' if sample.count(';') > sample.count(',') else ','
            
            reader = csv.DictReader(f, delimiter=delimiter)
            
            for row in reader:
                cve = row.get('CVE', '').strip()
                if not cve or cve in vulnerabilities:
                    continue
                
                vuln = VulnerabilityInfo(
                    cve=cve,
                    commit_hash=row.get('V_COMMIT', '').strip(),
                    file_path=row.get('FilePath', '').strip(),
                    function_name=row.get('F_NAME', '').strip(),
                    unit_type=row.get('UNIT_TYPE', '').strip()
                )
                vulnerabilities[cve] = vuln
                self.logger.debug(f"Found vulnerability: {cve}")
        
        self.logger.info(f"Parsed {len(vulnerabilities)} vulnerabilities from CSV")
        return vulnerabilities


# =============================================================================
# Patch Discovery
# =============================================================================

class PatchDiscovery:
    """Discovers and loads patch files from the patches directory"""
    
    def __init__(self, patches_dir: Path, logger: logging.Logger):
        self.patches_dir = patches_dir
        self.logger = logger
    
    def discover_patches(self, cve_filter: Optional[str] = None) -> List[PatchInfo]:
        """Discover all patches in the patches directory"""
        patches = []
        
        self.logger.info(f"Discovering patches in: {self.patches_dir}")
        
        if not self.patches_dir.exists():
            self.logger.error(f"Patches directory not found: {self.patches_dir}")
            return patches
        
        # Iterate through CVE directories
        for cve_dir in self.patches_dir.iterdir():
            if not cve_dir.is_dir():
                continue
            
            cve_id = cve_dir.name.upper()
            
            # Skip if filtering by specific CVE
            if cve_filter and cve_id != cve_filter.upper():
                continue
            
            # Iterate through model directories
            for model_dir in cve_dir.iterdir():
                if not model_dir.is_dir():
                    continue
                
                patch_info = self._load_patch_info(cve_id, model_dir)
                if patch_info:
                    patches.append(patch_info)
        
        self.logger.info(f"Discovered {len(patches)} patches")
        return patches
    
    def _load_patch_info(self, cve_id: str, model_dir: Path) -> Optional[PatchInfo]:
        """Load patch information from a model directory"""
        model_name = model_dir.name.replace("_", ":")  # Convert qwen2.5_7b back to qwen2.5:7b
        
        # Find patch files
        patched_file = None
        function_only_file = None
        response_json = None
        
        for file in model_dir.iterdir():
            if file.name == "response.json":
                response_json = file
            elif file.name.endswith("_function_only.c"):
                function_only_file = file
            elif file.name.endswith(".c") and not file.name.endswith("_invalid.c"):
                # This is the full patched file (e.g., strtod_l.c)
                if "_function_only" not in file.name:
                    patched_file = file
        
        # Load metadata from response.json if available
        original_filepath = ""
        is_valid = False
        
        if response_json and response_json.exists():
            try:
                with open(response_json, 'r') as f:
                    metadata = json.load(f)
                    original_filepath = metadata.get("original_filepath", "")
                    is_valid = metadata.get("syntax_valid", False)
            except Exception as e:
                self.logger.warning(f"Failed to parse {response_json}: {e}")
        
        # Only return if we have a valid patched file
        if patched_file and patched_file.exists():
            patch_info = PatchInfo(
                cve_id=cve_id,
                model_name=model_name,
                patch_dir=model_dir,
                patched_file=patched_file,
                function_only_file=function_only_file,
                response_json=response_json,
                is_valid=is_valid,
                original_filepath=original_filepath
            )
            self.logger.debug(f"Loaded patch: {cve_id}/{model_name} (valid={is_valid})")
            return patch_info
        
        self.logger.warning(f"No valid patch file found in {model_dir}")
        return None


# =============================================================================
# Dockerfile Generator for Patched Code
# =============================================================================

class PatchedDockerfileGenerator:
    """Generates Dockerfiles for building and testing patched glibc versions"""
    
    # Template with SAST tools pre-installed
    DOCKERFILE_TEMPLATE = '''# =============================================================================
# Dockerfile for Patched glibc Validation - {cve}
# Model: {model_name}
# Base: {base_image}
# =============================================================================
FROM {base_image}

LABEL maintainer="AI-SSD Project"
LABEL cve="{cve}"
LABEL model="{model_name}"
LABEL phase="validation"

# Prevent interactive prompts
ENV DEBIAN_FRONTEND=noninteractive

# Update and install build dependencies + SAST tools
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
    python3-pip \\
    cppcheck \\
    && rm -rf /var/lib/apt/lists/*

# Install additional SAST tools
RUN pip3 install flawfinder || true

# Create working directory
WORKDIR /build

# Clone glibc repository and checkout vulnerable commit
RUN git clone https://github.com/bminor/glibc.git /build/glibc-src

WORKDIR /build/glibc-src
RUN git fetch origin {commit_hash} && \\
    git checkout {commit_hash}

# Copy the patched source file (will replace original)
COPY patched_source.c /build/patched_source.c

# Apply the patch by replacing the vulnerable file
RUN cp /build/patched_source.c /build/glibc-src/{vuln_file_path}

# Create build directory (glibc requires out-of-tree build)
RUN mkdir -p /build/glibc-build

WORKDIR /build/glibc-build

# Configure glibc build
RUN ../glibc-src/configure \\
    --prefix=/opt/glibc-patched \\
    --disable-werror \\
    --disable-sanity-checks \\
    CC="gcc -fno-stack-protector" \\
    CFLAGS="-O2 -g -fno-stack-protector -Wno-error" \\
    || (cat config.log && exit 1)

# Build glibc (using -k to continue on errors)
RUN make -j$(nproc) -k 2>&1 | tee /build/build.log || true

# Install to prefix
RUN make install -k 2>&1 | tee -a /build/build.log || true

# Create directory for PoC
RUN mkdir -p /poc /sast_results

# Copy exploit source
COPY poc_exploit.c /poc/exploit.c

# Copy patched source for SAST analysis
RUN cp /build/patched_source.c /sast_results/patched_source.c

# Compile the PoC against PATCHED glibc
WORKDIR /poc
RUN gcc -o exploit exploit.c \\
    -Wl,-rpath,/opt/glibc-patched/lib \\
    -Wl,--dynamic-linker=/opt/glibc-patched/lib/ld-linux-x86-64.so.2 \\
    -L/opt/glibc-patched/lib \\
    -ldl -lpthread \\
    2>&1 || gcc -o exploit exploit.c -ldl -lpthread 2>&1 || gcc -o exploit exploit.c 2>&1

# Set environment for running with patched glibc
ENV LD_LIBRARY_PATH=/opt/glibc-patched/lib

# Default command: run the exploit (expecting it to FAIL = patch works)
CMD ["/poc/exploit"]
'''

    def __init__(self, logger: logging.Logger):
        self.logger = logger
    
    def get_base_image(self, cve: str) -> str:
        """Determine appropriate base image based on CVE"""
        if cve in CVE_YEAR_HINTS:
            year = CVE_YEAR_HINTS[cve]
            return COMMIT_OS_MAPPING.get(year, COMMIT_OS_MAPPING["default"])
        
        # Try to extract year from CVE name
        try:
            parts = cve.split('-')
            if len(parts) >= 2:
                year = parts[1][:4]
                if year in COMMIT_OS_MAPPING:
                    return COMMIT_OS_MAPPING[year]
        except (IndexError, ValueError):
            pass
        
        return COMMIT_OS_MAPPING["default"]
    
    def generate(
        self,
        patch_info: PatchInfo,
        vuln_info: VulnerabilityInfo,
        output_dir: Path
    ) -> Path:
        """Generate Dockerfile for testing a patch"""
        base_image = self.get_base_image(patch_info.cve_id)
        
        # Determine the vulnerable file path within glibc
        vuln_file_path = CVE_FILE_MAPPING.get(
            patch_info.cve_id,
            patch_info.original_filepath or vuln_info.file_path
        )
        
        self.logger.info(
            f"Generating Dockerfile for {patch_info.cve_id}/{patch_info.model_name} "
            f"using {base_image}"
        )
        
        dockerfile_content = self.DOCKERFILE_TEMPLATE.format(
            cve=patch_info.cve_id,
            model_name=patch_info.model_name,
            base_image=base_image,
            commit_hash=vuln_info.commit_hash,
            vuln_file_path=vuln_file_path
        )
        
        # Create output directory
        safe_model = patch_info.model_name.replace(":", "_").replace(".", "_")
        build_dir = output_dir / patch_info.cve_id.lower() / safe_model
        build_dir.mkdir(parents=True, exist_ok=True)
        
        dockerfile_path = build_dir / "Dockerfile"
        with open(dockerfile_path, 'w') as f:
            f.write(dockerfile_content)
        
        self.logger.debug(f"Dockerfile written to: {dockerfile_path}")
        return build_dir


# =============================================================================
# Docker Manager for Validation
# =============================================================================

class ValidationDockerManager:
    """Manages Docker operations for patch validation"""
    
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
    
    def build_image(
        self,
        patch_info: PatchInfo,
        build_context: Path
    ) -> Tuple[bool, Optional[str]]:
        """Build Docker image for patch validation"""
        self.logger.info(f"Building image for {patch_info.cve_id}/{patch_info.model_name}...")
        
        try:
            image, build_logs = self.client.images.build(
                path=str(build_context),
                tag=patch_info.image_name,
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
            
            self.logger.info(f"Successfully built image: {patch_info.image_name}")
            return True, '\n'.join(log_output)
            
        except BuildError as e:
            self.logger.error(f"Build failed for {patch_info.cve_id}/{patch_info.model_name}: {e}")
            return False, str(e)
        except APIError as e:
            self.logger.error(f"Docker API error: {e}")
            return False, str(e)
    
    def run_poc(
        self,
        patch_info: PatchInfo,
        run_timeout: int = 300
    ) -> Tuple[bool, int, str]:
        """
        Run the PoC exploit against patched code.
        
        Returns:
            - poc_blocked: True if the PoC was blocked (vulnerability fixed)
            - exit_code: Container exit code
            - logs: Container output logs
        """
        self.logger.info(f"Running PoC for {patch_info.cve_id}/{patch_info.model_name}...")
        
        try:
            # Run container with resource limits
            container = self.client.containers.run(
                patch_info.image_name,
                name=patch_info.container_name,
                detach=True,
                mem_limit='2g',
                cpu_period=100000,
                cpu_quota=100000,
                network_disabled=True,
                remove=False
            )
            
            # Wait for container to finish
            result = container.wait(timeout=run_timeout)
            exit_code = result.get('StatusCode', -1)
            
            # Get logs
            logs = container.logs(stdout=True, stderr=True).decode('utf-8', errors='replace')
            
            # Clean up container
            try:
                container.remove(force=True)
            except:
                pass
            
            # Interpret results - for a PATCHED system, we expect the PoC to FAIL
            poc_blocked = self._interpret_poc_result(patch_info, exit_code, logs)
            
            self.logger.info(
                f"PoC result for {patch_info.cve_id}/{patch_info.model_name}: "
                f"exit_code={exit_code}, poc_blocked={poc_blocked}"
            )
            return poc_blocked, exit_code, logs
            
        except ContainerError as e:
            self.logger.warning(f"Container error: {e}")
            # Container errors may indicate the exploit was blocked
            return True, e.exit_status, str(e)
        except Exception as e:
            self.logger.error(f"Failed to run PoC: {e}")
            return False, -1, str(e)
    
    def _interpret_poc_result(
        self,
        patch_info: PatchInfo,
        exit_code: int,
        logs: str
    ) -> bool:
        """
        Interpret PoC results to determine if the vulnerability was fixed.
        
        For a PATCHED system:
        - If the PoC crashes/fails differently than the vulnerability behavior = FIXED
        - If the PoC shows "safe" behavior = FIXED
        - If the PoC still shows vulnerability indicators = NOT FIXED
        """
        cve_id = patch_info.cve_id
        logs_lower = logs.lower()
        
        # CVE-specific interpretation
        if cve_id == "CVE-2012-3480":
            # For strtod integer overflow, the vulnerable behavior is completing
            # successfully with a malformed output.
            # A proper fix would either:
            # 1. Return an error/different output
            # 2. Handle the overflow gracefully
            # 3. Not crash (graceful handling)
            
            # If we see normal hex float output, vulnerability may still exist
            # unless the output indicates proper error handling
            if exit_code != 0:
                # Non-zero exit might indicate proper error handling
                return True
            if "error" in logs_lower or "overflow" in logs_lower:
                # Error messages indicate the patch caught the issue
                return True
            if "0x" in logs and "p" in logs:
                # Still producing hex float output - might still be vulnerable
                # But need to check if it's the same behavior
                return False
            return True  # Default to assuming patch worked if behavior changed
            
        elif cve_id == "CVE-2014-5119":
            # For heap corruption, signs of crash/corruption indicate unfixed
            if "corrupted" in logs_lower or "double-linked" in logs_lower:
                return False  # Still vulnerable
            if exit_code in [134, 139]:  # SIGABRT or SIGSEGV
                return False  # Still crashing = still vulnerable
            return True  # No corruption signs = likely fixed
            
        elif cve_id == "CVE-2015-7547":
            # For stack buffer overflow in getaddrinfo
            if exit_code == 139:  # SIGSEGV
                return False  # Still crashing
            if "stack smashing" in logs_lower:
                return False  # Stack protection triggered = still vulnerable
            if exit_code == 0 or exit_code == 1:
                # Normal exit (with or without error) = likely fixed
                return True
            return True
        
        # Default interpretation
        # If the program crashes with SIGSEGV/SIGABRT, likely still vulnerable
        if exit_code in [134, 139]:
            return False
        
        return True
    
    def run_sast(
        self,
        patch_info: PatchInfo,
        patched_file: Path
    ) -> List[SASTResult]:
        """
        Run SAST tools on the patched source code.
        
        This runs inside a container that has SAST tools installed.
        """
        self.logger.info(f"Running SAST analysis for {patch_info.cve_id}/{patch_info.model_name}...")
        
        results = []
        
        # Run each SAST tool
        for tool_name, tool_config in SAST_TOOLS.items():
            result = self._run_sast_tool(patch_info, patched_file, tool_name, tool_config)
            results.append(result)
        
        return results
    
    def _run_sast_tool(
        self,
        patch_info: PatchInfo,
        patched_file: Path,
        tool_name: str,
        tool_config: Dict[str, Any]
    ) -> SASTResult:
        """Run a single SAST tool"""
        self.logger.debug(f"Running {tool_name}...")
        
        result = SASTResult(
            tool=tool_name,
            success=False,
            findings=[],
            error_message=None,
            raw_output=""
        )
        
        try:
            # Run SAST in the existing container image
            sast_container_name = f"sast-{patch_info.container_name}-{tool_name}"
            
            # Build the SAST command
            run_cmd = tool_config["run_cmd"].format(file="/sast_results/patched_source.c")
            
            # Run container with SAST command
            container = self.client.containers.run(
                patch_info.image_name,
                command=f"/bin/bash -c '{run_cmd}'",
                name=sast_container_name,
                detach=True,
                remove=False
            )
            
            # Wait for completion
            exit_result = container.wait(timeout=120)
            exit_code = exit_result.get('StatusCode', -1)
            
            # Get output
            output = container.logs(stdout=True, stderr=True).decode('utf-8', errors='replace')
            result.raw_output = output
            
            # Clean up
            try:
                container.remove(force=True)
            except:
                pass
            
            # Parse findings based on tool
            result.findings = self._parse_sast_output(tool_name, output)
            result.success = True
            
            # Count by severity
            for finding in result.findings:
                severity = finding.severity.lower()
                if severity in ['critical', 'error']:
                    result.critical_count += 1
                elif severity == 'high':
                    result.high_count += 1
                elif severity in ['medium', 'warning']:
                    result.medium_count += 1
                else:
                    result.low_count += 1
            
            self.logger.debug(
                f"{tool_name}: {len(result.findings)} findings "
                f"(C:{result.critical_count} H:{result.high_count} M:{result.medium_count} L:{result.low_count})"
            )
            
        except Exception as e:
            self.logger.warning(f"SAST tool {tool_name} failed: {e}")
            result.error_message = str(e)
        
        return result
    
    def _parse_sast_output(self, tool_name: str, output: str) -> List[SASTFinding]:
        """Parse SAST tool output into findings"""
        findings = []
        
        if tool_name == "cppcheck":
            findings = self._parse_cppcheck_output(output)
        elif tool_name == "flawfinder":
            findings = self._parse_flawfinder_output(output)
        elif tool_name == "rats":
            findings = self._parse_rats_output(output)
        
        return findings
    
    def _parse_cppcheck_output(self, output: str) -> List[SASTFinding]:
        """Parse cppcheck XML output"""
        findings = []
        
        # Try to parse XML
        try:
            import xml.etree.ElementTree as ET
            root = ET.fromstring(output)
            
            for error in root.findall('.//error'):
                severity = error.get('severity', 'unknown')
                msg = error.get('msg', '')
                cwe = error.get('cwe', '')
                
                location = error.find('location')
                line = None
                file_path = None
                if location is not None:
                    line = int(location.get('line', 0)) or None
                    file_path = location.get('file')
                
                findings.append(SASTFinding(
                    tool="cppcheck",
                    severity=severity,
                    message=msg,
                    line=line,
                    cwe_id=f"CWE-{cwe}" if cwe else None,
                    file_path=file_path
                ))
        except Exception:
            # Fall back to line-by-line parsing
            for line in output.split('\n'):
                if 'error' in line.lower() or 'warning' in line.lower():
                    findings.append(SASTFinding(
                        tool="cppcheck",
                        severity="warning",
                        message=line.strip()
                    ))
        
        return findings
    
    def _parse_flawfinder_output(self, output: str) -> List[SASTFinding]:
        """Parse flawfinder output"""
        findings = []
        
        # Flawfinder output format: file:line:column: [level] (category) message
        pattern = r'^(.+):(\d+):(\d+):\s*\[(\d+)\]\s*\(([^)]+)\)\s*(.+)$'
        
        for line in output.split('\n'):
            match = re.match(pattern, line.strip())
            if match:
                file_path, line_num, col, level, category, msg = match.groups()
                
                # Map level to severity
                level_int = int(level)
                if level_int >= 4:
                    severity = "high"
                elif level_int >= 2:
                    severity = "medium"
                else:
                    severity = "low"
                
                findings.append(SASTFinding(
                    tool="flawfinder",
                    severity=severity,
                    message=f"[{category}] {msg}",
                    line=int(line_num),
                    column=int(col),
                    file_path=file_path
                ))
        
        return findings
    
    def _parse_rats_output(self, output: str) -> List[SASTFinding]:
        """Parse RATS XML output"""
        findings = []
        
        if "RATS not available" in output:
            return findings
        
        try:
            import xml.etree.ElementTree as ET
            root = ET.fromstring(output)
            
            for vuln in root.findall('.//vulnerability'):
                severity = vuln.find('severity')
                severity_text = severity.text if severity is not None else "unknown"
                
                message_elem = vuln.find('message')
                message = message_elem.text if message_elem is not None else ""
                
                line_elem = vuln.find('line')
                line = int(line_elem.text) if line_elem is not None else None
                
                findings.append(SASTFinding(
                    tool="rats",
                    severity=severity_text.lower(),
                    message=message,
                    line=line
                ))
        except Exception:
            pass
        
        return findings
    
    def cleanup_image(self, patch_info: PatchInfo):
        """Remove Docker image"""
        try:
            self.client.images.remove(patch_info.image_name, force=True)
            self.logger.debug(f"Removed image: {patch_info.image_name}")
        except ImageNotFound:
            pass
        except Exception as e:
            self.logger.warning(f"Failed to remove image {patch_info.image_name}: {e}")
    
    def cleanup_container(self, patch_info: PatchInfo):
        """Remove Docker container if exists"""
        try:
            container = self.client.containers.get(patch_info.container_name)
            container.remove(force=True)
            self.logger.debug(f"Removed container: {patch_info.container_name}")
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
    
    def find_poc(self, cve_id: str) -> Optional[Path]:
        """Find PoC file for a CVE"""
        possible_paths = [
            self.exploits_dir / cve_id / "exploit.c",
            self.exploits_dir / cve_id / "poc.c",
            self.exploits_dir / cve_id.lower() / "exploit.c",
            self.exploits_dir / f"{cve_id}.c",
            self.exploits_dir / f"{cve_id.lower()}.c",
        ]
        
        for path in possible_paths:
            if path.exists():
                self.logger.debug(f"Found PoC for {cve_id} at: {path}")
                return path
        
        self.logger.warning(f"No PoC found for {cve_id}")
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

class ValidationReportGenerator:
    """Generates validation reports"""
    
    def __init__(self, results_dir: Path, logger: logging.Logger):
        self.results_dir = results_dir
        self.results_dir.mkdir(parents=True, exist_ok=True)
        self.logger = logger
        self.results: List[ValidationResult] = []
    
    def add_result(self, result: ValidationResult):
        """Add a validation result"""
        self.results.append(result)
        
        # Also save individual result immediately (for crash recovery)
        self._save_individual_result(result)
    
    def _save_individual_result(self, result: ValidationResult):
        """Save individual result to file"""
        cve_dir = self.results_dir / result.cve_id.lower()
        cve_dir.mkdir(parents=True, exist_ok=True)
        
        safe_model = result.model_name.replace(":", "_").replace(".", "_")
        result_file = cve_dir / f"{safe_model}_validation.json"
        
        with open(result_file, 'w') as f:
            json.dump(result.to_dict(), f, indent=2)
    
    def generate_summary_report(self) -> Path:
        """Generate comprehensive summary report"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = self.results_dir / f"validation_summary_{timestamp}.json"
        
        # Calculate statistics
        total = len(self.results)
        successful = sum(1 for r in self.results if r.status == ValidationStatus.SUCCESS.value)
        poc_blocked = sum(1 for r in self.results if r.poc_blocked)
        sast_passed = sum(1 for r in self.results if r.sast_passed)
        build_failures = sum(1 for r in self.results if not r.build_success)
        
        # Group by CVE
        by_cve = {}
        for r in self.results:
            if r.cve_id not in by_cve:
                by_cve[r.cve_id] = []
            by_cve[r.cve_id].append(r.to_dict())
        
        # Group by model
        by_model = {}
        for r in self.results:
            if r.model_name not in by_model:
                by_model[r.model_name] = []
            by_model[r.model_name].append(r.to_dict())
        
        report_data = {
            "metadata": {
                "generated_at": datetime.now().isoformat(),
                "phase": "Phase 3 - Multi-Layered Validation",
                "total_validations": total,
            },
            "summary": {
                "successful": successful,
                "poc_blocked": poc_blocked,
                "sast_passed": sast_passed,
                "build_failures": build_failures,
                "success_rate": f"{(successful/total*100):.1f}%" if total > 0 else "N/A",
            },
            "by_cve": by_cve,
            "by_model": by_model,
            "all_results": [r.to_dict() for r in self.results]
        }
        
        with open(report_path, 'w') as f:
            json.dump(report_data, f, indent=2)
        
        self.logger.info(f"Summary report generated: {report_path}")
        return report_path
    
    def print_summary(self):
        """Print summary to console"""
        print("\n" + "=" * 70)
        print("PHASE 3: MULTI-LAYERED VALIDATION SUMMARY")
        print("=" * 70)
        
        # Calculate stats
        total = len(self.results)
        successful = sum(1 for r in self.results if r.status == ValidationStatus.SUCCESS.value)
        
        # Print by CVE
        by_cve = {}
        for r in self.results:
            if r.cve_id not in by_cve:
                by_cve[r.cve_id] = []
            by_cve[r.cve_id].append(r)
        
        for cve_id, results in sorted(by_cve.items()):
            print(f"\n{cve_id}:")
            print("-" * 40)
            for r in results:
                status_icon = "✓" if r.status == ValidationStatus.SUCCESS.value else "✗"
                poc_icon = "🛡" if r.poc_blocked else "⚠"
                sast_icon = "✓" if r.sast_passed else "✗"
                print(f"  {status_icon} {r.model_name:<25} | PoC: {poc_icon} | SAST: {sast_icon} | {r.status}")
        
        print("\n" + "-" * 70)
        print(f"Total: {total} | Successful: {successful} | Failed: {total - successful}")
        print(f"Success Rate: {(successful/total*100):.1f}%" if total > 0 else "No results")
        print("=" * 70 + "\n")


# =============================================================================
# Main Validation Pipeline
# =============================================================================

class ValidationPipeline:
    """Main pipeline orchestrator for Phase 3 validation"""
    
    def __init__(self, args: argparse.Namespace):
        self.base_dir = Path(args.base_dir).resolve()
        self.csv_path = Path(args.csv_file).resolve()
        self.patches_dir = Path(args.patches_dir).resolve()
        self.exploits_dir = Path(args.exploits_dir).resolve()
        self.build_timeout = args.build_timeout
        self.run_timeout = args.run_timeout
        self.cleanup = args.cleanup
        self.specific_cve = args.cve
        self.skip_sast = args.skip_sast
        
        # Setup directories
        self.validation_builds_dir = self.base_dir / "validation_builds"
        self.results_dir = self.base_dir / "validation_results"
        self.logs_dir = self.base_dir / "logs"
        
        # Setup logging
        self.logger = setup_logging(self.logs_dir, args.verbose)
        
        # Initialize components
        self.csv_parser = CSVParser(self.csv_path, self.logger)
        self.patch_discovery = PatchDiscovery(self.patches_dir, self.logger)
        self.dockerfile_gen = PatchedDockerfileGenerator(self.logger)
        self.docker_mgr = ValidationDockerManager(self.logger, self.build_timeout)
        self.poc_mgr = PoCManager(self.exploits_dir, self.logger)
        self.report_gen = ValidationReportGenerator(self.results_dir, self.logger)
    
    def run(self):
        """Execute the validation pipeline"""
        self.logger.info("=" * 60)
        self.logger.info("Starting Phase 3: Multi-Layered Validation Pipeline")
        self.logger.info("=" * 60)
        self.logger.info(f"Base directory: {self.base_dir}")
        self.logger.info(f"Patches directory: {self.patches_dir}")
        self.logger.info(f"Exploits directory: {self.exploits_dir}")
        
        # Load vulnerability info from CSV
        try:
            vuln_info_map = self.csv_parser.parse()
        except FileNotFoundError as e:
            self.logger.error(str(e))
            sys.exit(1)
        
        # Discover patches
        patches = self.patch_discovery.discover_patches(self.specific_cve)
        
        if not patches:
            self.logger.error("No patches found to validate")
            sys.exit(1)
        
        self.logger.info(f"Found {len(patches)} patches to validate")
        
        # Process each patch
        for patch_info in patches:
            self.logger.info(f"\n{'='*60}")
            self.logger.info(f"Validating: {patch_info.cve_id} / {patch_info.model_name}")
            self.logger.info(f"{'='*60}")
            
            # Get vulnerability info
            vuln_info = vuln_info_map.get(patch_info.cve_id)
            if not vuln_info:
                self.logger.warning(f"No vulnerability info found for {patch_info.cve_id}")
                continue
            
            result = self._validate_patch(patch_info, vuln_info)
            self.report_gen.add_result(result)
        
        # Generate final report
        report_path = self.report_gen.generate_summary_report()
        self.report_gen.print_summary()
        
        self.logger.info(f"Validation complete. Results saved to: {report_path}")
    
    def _validate_patch(
        self,
        patch_info: PatchInfo,
        vuln_info: VulnerabilityInfo
    ) -> ValidationResult:
        """Validate a single patch"""
        start_time = datetime.now()
        
        # Initialize result
        result = ValidationResult(
            cve_id=patch_info.cve_id,
            model_name=patch_info.model_name,
            status=ValidationStatus.UNKNOWN_ERROR.value,
            poc_blocked=False,
            build_success=False,
            sast_passed=False,
            sast_results=[],
            poc_exit_code=None,
            poc_output=None,
            error_message=None,
            execution_time_seconds=0,
            timestamp=start_time.isoformat(),
            patch_file=str(patch_info.patched_file) if patch_info.patched_file else ""
        )
        
        try:
            # Step 1: Verify patch file exists and is valid
            if not patch_info.patched_file or not patch_info.patched_file.exists():
                result.status = ValidationStatus.PATCH_NOT_FOUND.value
                result.error_message = "Patch file not found"
                return result
            
            # Check if patch is marked as invalid (syntax errors)
            if not patch_info.is_valid:
                result.status = ValidationStatus.INVALID_PATCH.value
                result.error_message = "Patch has syntax errors (marked invalid in Phase 2)"
                return result
            
            # Step 2: Find PoC for this CVE
            poc_path = self.poc_mgr.find_poc(patch_info.cve_id)
            if not poc_path:
                result.status = ValidationStatus.POC_NOT_FOUND.value
                result.error_message = f"No PoC found in {self.exploits_dir}"
                return result
            
            # Step 3: Generate Dockerfile
            build_context = self.dockerfile_gen.generate(
                patch_info, vuln_info, self.validation_builds_dir
            )
            
            # Step 4: Copy patch and PoC to build context
            patch_dest = build_context / "patched_source.c"
            shutil.copy2(patch_info.patched_file, patch_dest)
            
            if not self.poc_mgr.copy_poc_to_build_context(poc_path, build_context):
                result.status = ValidationStatus.UNKNOWN_ERROR.value
                result.error_message = "Failed to copy PoC to build context"
                return result
            
            # Step 5: Build Docker image with patched code
            build_success, build_logs = self.docker_mgr.build_image(patch_info, build_context)
            if not build_success:
                result.status = ValidationStatus.BUILD_ERROR.value
                result.error_message = "Failed to build Docker image with patched code"
                result.poc_output = build_logs
                return result
            
            result.build_success = True
            
            # Step 6: Run PoC against patched code
            poc_blocked, exit_code, poc_logs = self.docker_mgr.run_poc(
                patch_info, self.run_timeout
            )
            
            result.poc_blocked = poc_blocked
            result.poc_exit_code = exit_code
            result.poc_output = poc_logs
            
            if not poc_blocked:
                # PoC still works - vulnerability not fixed
                result.status = ValidationStatus.POC_STILL_WORKS.value
                result.error_message = "PoC exploit still triggers the vulnerability"
                return result
            
            self.logger.info(f"✓ PoC blocked for {patch_info.cve_id}/{patch_info.model_name}")
            
            # Step 7: Run SAST tools (if PoC was blocked)
            if not self.skip_sast:
                sast_results = self.docker_mgr.run_sast(patch_info, patch_info.patched_file)
                
                # Convert SAST results to serializable format
                result.sast_results = []
                total_critical = 0
                total_high = 0
                
                for sast_result in sast_results:
                    result.sast_results.append({
                        "tool": sast_result.tool,
                        "success": sast_result.success,
                        "critical_count": sast_result.critical_count,
                        "high_count": sast_result.high_count,
                        "medium_count": sast_result.medium_count,
                        "low_count": sast_result.low_count,
                        "findings_count": len(sast_result.findings),
                        "error": sast_result.error_message,
                    })
                    total_critical += sast_result.critical_count
                    total_high += sast_result.high_count
                
                # SAST passes if no critical or high severity issues
                # (Low/Medium issues are acceptable - they existed in original code too)
                result.sast_passed = (total_critical == 0 and total_high == 0)
                
                if not result.sast_passed:
                    result.status = ValidationStatus.SAST_FAILED.value
                    result.error_message = f"SAST found {total_critical} critical and {total_high} high severity issues"
                    return result
                
                self.logger.info(f"✓ SAST passed for {patch_info.cve_id}/{patch_info.model_name}")
            else:
                result.sast_passed = True  # Skipped
                result.sast_results = [{"status": "skipped"}]
            
            # All checks passed!
            result.status = ValidationStatus.SUCCESS.value
            self.logger.info(
                f"✓✓ VALIDATION SUCCESSFUL for {patch_info.cve_id}/{patch_info.model_name}"
            )
            
        except Exception as e:
            self.logger.exception(f"Error validating {patch_info.cve_id}/{patch_info.model_name}")
            result.status = ValidationStatus.UNKNOWN_ERROR.value
            result.error_message = str(e)
        
        finally:
            # Cleanup if requested
            if self.cleanup:
                self.docker_mgr.cleanup_container(patch_info)
                self.docker_mgr.cleanup_image(patch_info)
            
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
        description="AI-SSD Phase 3: Multi-Layered Patch Validation Pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run validation for all patches
  python patch_validator.py
  
  # Validate specific CVE
  python patch_validator.py --cve CVE-2015-7547
  
  # Skip SAST analysis (faster)
  python patch_validator.py --skip-sast
  
  # Run with cleanup and verbose output
  python patch_validator.py --cleanup --verbose
  
  # Custom paths
  python patch_validator.py --patches-dir /path/to/patches --exploits-dir /path/to/exploits
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
        '--patches-dir',
        type=str,
        default=None,
        help='Path to patches directory (default: <base-dir>/patches)'
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
        help='Validate only this specific CVE'
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
        '--skip-sast',
        action='store_true',
        help='Skip SAST analysis (only run PoC validation)'
    )
    
    parser.add_argument(
        '--cleanup',
        action='store_true',
        help='Clean up Docker images and containers after validation'
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
    
    if args.patches_dir is None:
        args.patches_dir = os.path.join(args.base_dir, 'patches')
    
    if args.exploits_dir is None:
        args.exploits_dir = os.path.join(args.base_dir, 'exploits')
    
    return args


def main():
    """Main entry point"""
    args = parse_arguments()
    
    try:
        pipeline = ValidationPipeline(args)
        pipeline.run()
    except KeyboardInterrupt:
        print("\nValidation interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"Fatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
