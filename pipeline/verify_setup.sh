#!/bin/bash
# =============================================================================
# AI-SSD Project - Verify Setup Script
# =============================================================================
# Quick script to verify all prerequisites are in place for all phases:
# Phase 1: Vulnerability Reproduction
# Phase 2: Automated Patch Generation  
# Phase 3: Multi-Layered Validation
# Phase 4: Automated Reporting
# Master Pipeline & Cleanup Utilities
# =============================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo ""
echo "============================================="
echo "AI-SSD Pipeline Setup Verification"
echo "============================================="
echo ""

ERRORS=0
WARNINGS=0

echo -e "${BLUE}--- Core Dependencies ---${NC}"

# Check Docker
echo -n "Checking Docker... "
if command -v docker &> /dev/null && docker info &> /dev/null; then
    echo -e "${GREEN}✓${NC} $(docker --version | cut -d',' -f1)"
else
    echo -e "${RED}✗ Docker not installed or not running${NC}"
    ERRORS=$((ERRORS + 1))
fi

# Check Python
echo -n "Checking Python 3... "
if command -v python3 &> /dev/null; then
    echo -e "${GREEN}✓${NC} $(python3 --version)"
else
    echo -e "${RED}✗ Python 3 not installed${NC}"
    ERRORS=$((ERRORS + 1))
fi

# Check Python docker package
echo -n "Checking Python docker package... "
if python3 -c "import docker" &> /dev/null; then
    echo -e "${GREEN}✓${NC} Installed"
else
    echo -e "${RED}✗ Not installed (run: pip3 install docker)${NC}"
    ERRORS=$((ERRORS + 1))
fi

# Check Python requests package (Phase 2)
echo -n "Checking Python requests package... "
if python3 -c "import requests" &> /dev/null; then
    echo -e "${GREEN}✓${NC} Installed"
else
    echo -e "${RED}✗ Not installed (run: pip3 install requests)${NC}"
    ERRORS=$((ERRORS + 1))
fi

# Check Python yaml package
echo -n "Checking Python pyyaml package... "
if python3 -c "import yaml" &> /dev/null; then
    echo -e "${GREEN}✓${NC} Installed"
else
    echo -e "${RED}✗ Not installed (run: pip3 install pyyaml)${NC}"
    ERRORS=$((ERRORS + 1))
fi

# Check Python matplotlib package (Phase 4)
echo -n "Checking Python matplotlib package... "
if python3 -c "import matplotlib" &> /dev/null; then
    echo -e "${GREEN}✓${NC} Installed"
else
    echo -e "${YELLOW}⚠${NC} Not installed (run: pip3 install matplotlib) - needed for Phase 4"
    WARNINGS=$((WARNINGS + 1))
fi

# Check Python numpy package (Phase 4)
echo -n "Checking Python numpy package... "
if python3 -c "import numpy" &> /dev/null; then
    echo -e "${GREEN}✓${NC} Installed"
else
    echo -e "${YELLOW}⚠${NC} Not installed (run: pip3 install numpy) - needed for Phase 4"
    WARNINGS=$((WARNINGS + 1))
fi

echo ""
echo -e "${BLUE}--- Phase 1: Vulnerability Reproduction ---${NC}"

# Check CSV file
echo -n "Checking file-function.csv... "
if [ -f "$SCRIPT_DIR/documentation/file-function.csv" ]; then
    COUNT=$(tail -n +2 "$SCRIPT_DIR/documentation/file-function.csv" | grep -c "CVE-" || true)
    echo -e "${GREEN}✓${NC} Found ($COUNT CVE entries)"
else
    echo -e "${RED}✗ Not found at documentation/file-function.csv${NC}"
    ERRORS=$((ERRORS + 1))
fi

# Check exploits directory
echo -n "Checking exploits directory... "
if [ -d "$SCRIPT_DIR/exploits" ]; then
    POC_COUNT=$(find "$SCRIPT_DIR/exploits" -name "CVE-*.c" | wc -l | tr -d ' ')
    echo -e "${GREEN}✓${NC} Found ($POC_COUNT PoC files)"
    
    # List available PoCs
    echo "  Available PoCs:"
    for poc in "$SCRIPT_DIR/exploits"/CVE-*.c; do
        if [ -f "$poc" ]; then
            echo "    - $(basename "$poc")"
        fi
    done
else
    echo -e "${RED}✗ Exploits directory not found${NC}"
    ERRORS=$((ERRORS + 1))
fi

# Check orchestrator.py
echo -n "Checking orchestrator.py... "
if [ -f "$SCRIPT_DIR/orchestrator.py" ]; then
    echo -e "${GREEN}✓${NC} Found"
else
    echo -e "${RED}✗ Not found${NC}"
    ERRORS=$((ERRORS + 1))
fi

echo ""
echo -e "${BLUE}--- Phase 2: Patch Generation ---${NC}"

# Check patch_generator.py
echo -n "Checking patch_generator.py... "
if [ -f "$SCRIPT_DIR/patch_generator.py" ]; then
    echo -e "${GREEN}✓${NC} Found"
else
    echo -e "${RED}✗ Not found${NC}"
    ERRORS=$((ERRORS + 1))
fi

# Check patches directory
echo -n "Checking patches directory... "
if [ -d "$SCRIPT_DIR/patches" ]; then
    echo -e "${GREEN}✓${NC} Found"
else
    echo -e "${YELLOW}⚠${NC} Not found (will be created on first run)"
    WARNINGS=$((WARNINGS + 1))
fi

# Check config.yaml
echo -n "Checking config.yaml... "
if [ -f "$SCRIPT_DIR/config.yaml" ]; then
    if grep -q "llm:" "$SCRIPT_DIR/config.yaml"; then
        echo -e "${GREEN}✓${NC} Found (with LLM config)"
    else
        echo -e "${YELLOW}⚠${NC} Found (missing LLM config)"
        WARNINGS=$((WARNINGS + 1))
    fi
else
    echo -e "${RED}✗ Not found${NC}"
    ERRORS=$((ERRORS + 1))
fi

# Check LLM endpoint connectivity
echo -n "Checking LLM API connectivity... "
LLM_ENDPOINT=$(grep -A1 "llm:" "$SCRIPT_DIR/config.yaml" 2>/dev/null | grep "endpoint:" | sed 's/.*endpoint: *"\([^"]*\)".*/\1/' | tr -d '"' | head -1)
if [ -z "$LLM_ENDPOINT" ]; then
    LLM_ENDPOINT="http://10.3.2.171:80/api/chat"
fi
# Extract base URL for tags endpoint
LLM_BASE=$(echo "$LLM_ENDPOINT" | sed 's|/api/chat|/api/tags|')
if curl -s --connect-timeout 5 "$LLM_BASE" > /dev/null 2>&1; then
    echo -e "${GREEN}✓${NC} Reachable ($LLM_ENDPOINT)"
else
    echo -e "${YELLOW}⚠${NC} Cannot reach LLM API ($LLM_ENDPOINT)"
    WARNINGS=$((WARNINGS + 1))
fi

echo ""
echo -e "${BLUE}--- Phase 3: Patch Validation ---${NC}"

# Check patch_validator.py
echo -n "Checking patch_validator.py... "
if [ -f "$SCRIPT_DIR/patch_validator.py" ]; then
    echo -e "${GREEN}✓${NC} Found"
else
    echo -e "${RED}✗ Not found${NC}"
    ERRORS=$((ERRORS + 1))
fi

# Check Cppcheck (SAST tool)
echo -n "Checking Cppcheck (SAST)... "
if command -v cppcheck &> /dev/null; then
    echo -e "${GREEN}✓${NC} $(cppcheck --version)"
else
    echo -e "${YELLOW}⚠${NC} Not installed (run: apt install cppcheck)"
    WARNINGS=$((WARNINGS + 1))
fi

# Check Flawfinder (SAST tool)
echo -n "Checking Flawfinder (SAST)... "
if command -v flawfinder &> /dev/null; then
    echo -e "${GREEN}✓${NC} $(flawfinder --version 2>&1 | head -1)"
else
    echo -e "${YELLOW}⚠${NC} Not installed (run: pip3 install flawfinder)"
    WARNINGS=$((WARNINGS + 1))
fi

# Check validation_builds directory
echo -n "Checking validation_builds directory... "
if [ -d "$SCRIPT_DIR/validation_builds" ]; then
    echo -e "${GREEN}✓${NC} Found"
else
    echo -e "${YELLOW}⚠${NC} Not found (will be created on first run)"
    WARNINGS=$((WARNINGS + 1))
fi

# Check validation results directory
echo -n "Checking validation_results directory... "
if [ -d "$SCRIPT_DIR/validation_results" ]; then
    # Count existing validation results
    RESULT_COUNT=$(find "$SCRIPT_DIR/validation_results" -name "*_validation.json" -type f 2>/dev/null | wc -l | tr -d ' ')
    if [ "$RESULT_COUNT" -gt 0 ]; then
        echo -e "${GREEN}✓${NC} Found ($RESULT_COUNT validation results)"
    else
        echo -e "${GREEN}✓${NC} Found (no previous results)"
    fi
else
    echo -e "${YELLOW}⚠${NC} Not found (will be created on first run)"
    WARNINGS=$((WARNINGS + 1))
fi

# Check generated patches for validation
echo -n "Checking patches for validation... "
if [ -d "$SCRIPT_DIR/patches" ]; then
    PATCH_COUNT=$(find "$SCRIPT_DIR/patches" -name "*.c" -type f 2>/dev/null | wc -l | tr -d ' ')
    MODEL_COUNT=$(find "$SCRIPT_DIR/patches" -mindepth 1 -maxdepth 1 -type d ! -name ".*" 2>/dev/null | wc -l | tr -d ' ')
    if [ "$PATCH_COUNT" -gt 0 ]; then
        echo -e "${GREEN}✓${NC} $PATCH_COUNT patches from $MODEL_COUNT models ready for validation"
    else
        echo -e "${YELLOW}⚠${NC} No patches found (run Phase 2 first)"
        WARNINGS=$((WARNINGS + 1))
    fi
else
    echo -e "${YELLOW}⚠${NC} Patches directory not found (run Phase 2 first)"
    WARNINGS=$((WARNINGS + 1))
fi

echo ""
echo -e "${BLUE}--- Phase 4: Automated Reporting ---${NC}"

# Check reporter.py
echo -n "Checking reporter.py... "
if [ -f "$SCRIPT_DIR/reporter.py" ]; then
    echo -e "${GREEN}✓${NC} Found"
else
    echo -e "${RED}✗ Not found${NC}"
    ERRORS=$((ERRORS + 1))
fi

# Check reports directory
echo -n "Checking reports directory... "
if [ -d "$SCRIPT_DIR/reports" ]; then
    REPORT_COUNT=$(find "$SCRIPT_DIR/reports" -name "*.md" -type f 2>/dev/null | wc -l | tr -d ' ')
    if [ "$REPORT_COUNT" -gt 0 ]; then
        echo -e "${GREEN}✓${NC} Found ($REPORT_COUNT reports generated)"
    else
        echo -e "${GREEN}✓${NC} Found (no reports yet)"
    fi
else
    echo -e "${YELLOW}⚠${NC} Not found (will be created on first run)"
    WARNINGS=$((WARNINGS + 1))
fi

echo ""
echo -e "${BLUE}--- Master Pipeline & Utilities ---${NC}"

# Check pipeline.py
echo -n "Checking pipeline.py (master orchestrator)... "
if [ -f "$SCRIPT_DIR/pipeline.py" ]; then
    echo -e "${GREEN}✓${NC} Found"
else
    echo -e "${RED}✗ Not found${NC}"
    ERRORS=$((ERRORS + 1))
fi

# Check cleanup.py
echo -n "Checking cleanup.py... "
if [ -f "$SCRIPT_DIR/cleanup.py" ]; then
    echo -e "${GREEN}✓${NC} Found"
else
    echo -e "${YELLOW}⚠${NC} Not found (optional utility)"
    WARNINGS=$((WARNINGS + 1))
fi

echo ""
echo -e "${BLUE}--- System Resources ---${NC}"

# Check disk space
echo -n "Checking available disk space... "
AVAILABLE=$(df -BG "$SCRIPT_DIR" | tail -1 | awk '{print $4}' | sed 's/G//')
if [ "$AVAILABLE" -gt 20 ]; then
    echo -e "${GREEN}✓${NC} ${AVAILABLE}GB available"
else
    echo -e "${YELLOW}⚠${NC} Only ${AVAILABLE}GB available (recommend 20GB+)"
    WARNINGS=$((WARNINGS + 1))
fi

# Check memory
echo -n "Checking available memory... "
if command -v free &> /dev/null; then
    MEM_GB=$(free -g | awk '/^Mem:/{print $2}')
    if [ "$MEM_GB" -ge 4 ]; then
        echo -e "${GREEN}✓${NC} ${MEM_GB}GB RAM"
    else
        echo -e "${YELLOW}⚠${NC} Only ${MEM_GB}GB RAM (recommend 4GB+)"
        WARNINGS=$((WARNINGS + 1))
    fi
else
    # macOS
    if command -v sysctl &> /dev/null; then
        MEM_BYTES=$(sysctl -n hw.memsize 2>/dev/null || echo 0)
        MEM_GB=$((MEM_BYTES / 1024 / 1024 / 1024))
        echo -e "${GREEN}✓${NC} ${MEM_GB}GB RAM"
    else
        echo -e "${YELLOW}?${NC} Could not determine"
    fi
fi

echo ""
echo "============================================="

if [ $ERRORS -eq 0 ] && [ $WARNINGS -eq 0 ]; then
    echo -e "${GREEN}All checks passed!${NC}"
elif [ $ERRORS -eq 0 ]; then
    echo -e "${YELLOW}All critical checks passed ($WARNINGS warning(s))${NC}"
else
    echo -e "${RED}$ERRORS check(s) failed${NC}"
fi

echo ""
echo "Usage:"
echo "  Full Pipeline (all phases):"
echo "    python3 pipeline.py --verbose"
echo "    python3 pipeline.py --cve CVE-2015-7547 --verbose"
echo "    python3 pipeline.py --phases 2,3,4 --verbose"
echo "    python3 pipeline.py --dry-run"
echo ""
echo "  Phase 1 - Reproduce vulnerabilities:"
echo "    python3 orchestrator.py --verbose"
echo "    python3 orchestrator.py --cve CVE-2015-7547 --verbose"
echo ""
echo "  Phase 2 - Generate patches:"
echo "    python3 patch_generator.py --verbose"
echo "    python3 patch_generator.py --cve CVE-2015-7547 --verbose"
echo "    python3 patch_generator.py --models qwen2.5:7b --verbose"
echo ""
echo "  Phase 3 - Validate patches:"
echo "    python3 patch_validator.py --verbose"
echo "    python3 patch_validator.py --cve CVE-2015-7547 --verbose"
echo "    python3 patch_validator.py --skip-sast --verbose"
echo "    python3 patch_validator.py --cleanup --verbose"
echo ""
echo "  Phase 4 - Generate reports:"
echo "    python3 reporter.py --verbose"
echo "    python3 reporter.py --output-dir ./custom_reports"
echo ""
echo "  Cleanup - Remove generated artifacts:"
echo "    python3 cleanup.py --dry-run"
echo "    python3 cleanup.py --all"
echo "    python3 cleanup.py --phases 2,3 --interactive"
echo ""

if [ $ERRORS -gt 0 ]; then
    echo "Please fix the issues above before running the pipeline."
    echo "Run 'sudo ./setup.sh' to install missing dependencies."
fi

echo "============================================="
echo ""

exit $ERRORS