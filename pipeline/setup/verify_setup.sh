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

# NOTE: intentionally NO `set -e`. This is a tally script — every check handles
# its own success/failure via the ERRORS/WARNINGS counters and it exits with
# $ERRORS at the end. Under `set -e` a single failing probe (e.g. the NVD curl
# timing out when the network is flaky) would abort the whole script mid-run.

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PIPELINE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Pipeline config whose phase0_config points at the project YAML (with the
# sast: section). Override with: ./setup/verify_setup.sh --config <file>
PIPELINE_CONFIG="$PIPELINE_ROOT/config.yaml"
while [ $# -gt 0 ]; do
    case "$1" in
        --config) PIPELINE_CONFIG="$2"; shift 2 ;;
        --config=*) PIPELINE_CONFIG="${1#*=}"; shift ;;
        *) shift ;;
    esac
done

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

# Check Python openai package (Phase 2)
echo -n "Checking Python openai package... "
if python3 -c "import openai" &> /dev/null; then
    echo -e "${GREEN}✓${NC} Installed"
else
    echo -e "${RED}✗ Not installed (run: pip3 install openai)${NC}"
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
echo -e "${BLUE}--- API Keys ---${NC}"

# Check NVD API Key — resolve from env, the pipeline-root file, or the
# nvd_api_key value in any cve_aggregator/*_config.yaml, then validate it live.
echo -n "Checking NVD API Key... "
NVD_KEY="${NVD_API_KEY:-}"
if [ -z "$NVD_KEY" ] && [ -s "$PIPELINE_ROOT/API-nvd-key" ]; then
    NVD_KEY="$(tr -d '[:space:]' < "$PIPELINE_ROOT/API-nvd-key")"
fi
if [ -z "$NVD_KEY" ]; then
    NVD_KEY="$(grep -rhoE '^[[:space:]]*nvd_api_key:[[:space:]]*"[^"]+"' "$PIPELINE_ROOT"/cve_aggregator/*_config.yaml 2>/dev/null \
        | sed -E 's/.*"([^"]+)".*/\1/' | head -1)"
fi
if [ -z "$NVD_KEY" ]; then
    echo -e "${YELLOW}⚠${NC} No key found (env NVD_API_KEY, $PIPELINE_ROOT/API-nvd-key, or nvd_api_key in YAML) — fetch will be heavily rate-limited"
    WARNINGS=$((WARNINGS + 1))
else
    # Live validation: 200 with the key proves it is accepted by NVD. NVD 503s
    # routinely even for valid keys, so retry a few times before warning; a
    # 403/404 is a definitive rejection and breaks out immediately.
    NVD_CODE="000"
    for _try in 1 2 3; do
        # Fail fast: bounded connect + total time so a slow/unreachable NVD
        # can't make verification feel hung. `|| NVD_CODE=000` keeps a curl
        # non-zero exit from aborting the loop.
        NVD_CODE=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 --max-time 12 \
            -H "apiKey: $NVD_KEY" \
            "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=1" 2>/dev/null) || NVD_CODE="000"
        NVD_CODE="${NVD_CODE:-000}"
        case "$NVD_CODE" in
            200|403|404) break ;;
            *) [ "$_try" -lt 3 ] && sleep 2 ;;
        esac
    done
    if [ "$NVD_CODE" = "200" ]; then
        echo -e "${GREEN}✓${NC} Found and validated against NVD (HTTP 200)"
    elif [ "$NVD_CODE" = "404" ] || [ "$NVD_CODE" = "403" ]; then
        echo -e "${RED}✗${NC} Key rejected by NVD (HTTP $NVD_CODE) — check the key value"
        ERRORS=$((ERRORS + 1))
    else
        echo -e "${YELLOW}⚠${NC} Found, but NVD unreachable/flaky (HTTP $NVD_CODE) — likely transient, key may still be fine"
        WARNINGS=$((WARNINGS + 1))
    fi
fi

# Check OpenAI API Key
echo -n "Checking OpenAI API Key... "
if [ -s "$PIPELINE_ROOT/API-openai-key" ]; then
    echo -e "${GREEN}✓${NC} Found and not empty"
else
    echo -e "${YELLOW}⚠${NC} Not found or empty at $PIPELINE_ROOT/API-openai-key"
    WARNINGS=$((WARNINGS + 1))
fi

echo ""
echo -e "${BLUE}--- Phase 1: Vulnerability Reproduction ---${NC}"

# Check CSV file
echo -n "Checking file-function.csv... "
if [ -f "$PIPELINE_ROOT/documentation/file-function.csv" ]; then
    COUNT=$(tail -n +2 "$PIPELINE_ROOT/documentation/file-function.csv" | grep -c "CVE-" || true)
    echo -e "${GREEN}✓${NC} Found ($COUNT CVE entries)"
else
    echo -e "${RED}✗ Not found at documentation/file-function.csv${NC}"
    ERRORS=$((ERRORS + 1))
fi

# Check exploits directory
echo -n "Checking exploits directory... "
if [ -d "$PIPELINE_ROOT/exploits" ]; then
    POC_COUNT=$(find "$PIPELINE_ROOT/exploits" -name "CVE-*.c" | wc -l | tr -d ' ')
    echo -e "${GREEN}✓${NC} Found ($POC_COUNT PoC files)"
    
    # List available PoCs
    echo "  Available PoCs:"
    for poc in "$PIPELINE_ROOT/exploits"/CVE-*.c; do
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
if [ -f "$PIPELINE_ROOT/orchestrator.py" ]; then
    echo -e "${GREEN}✓${NC} Found"
else
    echo -e "${RED}✗ Not found${NC}"
    ERRORS=$((ERRORS + 1))
fi

echo ""
echo -e "${BLUE}--- Phase 2: Patch Generation ---${NC}"

# Check patch_generator.py
echo -n "Checking patch_generator.py... "
if [ -f "$PIPELINE_ROOT/patch_generator.py" ]; then
    echo -e "${GREEN}✓${NC} Found"
else
    echo -e "${RED}✗ Not found${NC}"
    ERRORS=$((ERRORS + 1))
fi

# Check patches directory
echo -n "Checking patches directory... "
if [ -d "$PIPELINE_ROOT/patches" ]; then
    echo -e "${GREEN}✓${NC} Found"
else
    echo -e "${YELLOW}⚠${NC} Not found (will be created on first run)"
    WARNINGS=$((WARNINGS + 1))
fi

# Check config.yaml
echo -n "Checking config.yaml... "
if [ -f "$PIPELINE_ROOT/config.yaml" ]; then
    if grep -q "llm:" "$PIPELINE_ROOT/config.yaml"; then
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
LLM_ENDPOINT=$(grep -A1 "llm:" "$PIPELINE_ROOT/config.yaml" 2>/dev/null | grep "endpoint:" | sed 's/.*endpoint: *"\([^"]*\)".*/\1/' | tr -d '"' | head -1)
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
if [ -f "$PIPELINE_ROOT/patch_validator.py" ]; then
    echo -e "${GREEN}✓${NC} Found"
else
    echo -e "${RED}✗ Not found${NC}"
    ERRORS=$((ERRORS + 1))
fi

# Check configured SAST tools (from the project YAML's sast: section).
# A configured-but-missing tool is a hard ERROR: the project explicitly asked
# for it, so Phase 3 must not run with reduced static-analysis coverage.
if [ "$(cd "$PIPELINE_ROOT" && python3 -m master_pipeline.sast_config --config "$PIPELINE_CONFIG" --enabled 2>/dev/null)" = "true" ]; then
    while IFS=$'\t' read -r name status hint; do
        [ -z "$name" ] && continue
        echo -n "Checking SAST tool '$name'... "
        if [ "$status" = "OK" ]; then
            echo -e "${GREEN}✓${NC} installed"
        else
            echo -e "${RED}✗ Not installed${NC} ($hint)"
            ERRORS=$((ERRORS + 1))
        fi
    done < <(cd "$PIPELINE_ROOT" && python3 -m master_pipeline.sast_config --config "$PIPELINE_CONFIG" --check 2>/dev/null)
else
    echo -e "Checking SAST tools... ${YELLOW}⚠${NC} disabled in project config (skipped)"
fi

# Check validation_builds directory
echo -n "Checking validation_builds directory... "
if [ -d "$PIPELINE_ROOT/validation_builds" ]; then
    echo -e "${GREEN}✓${NC} Found"
else
    echo -e "${YELLOW}⚠${NC} Not found (will be created on first run)"
    WARNINGS=$((WARNINGS + 1))
fi

# Check validation results directory
echo -n "Checking validation_results directory... "
if [ -d "$PIPELINE_ROOT/validation_results" ]; then
    # Count existing validation results
    RESULT_COUNT=$(find "$PIPELINE_ROOT/validation_results" -name "*_validation.json" -type f 2>/dev/null | wc -l | tr -d ' ')
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
if [ -d "$PIPELINE_ROOT/patches" ]; then
    PATCH_COUNT=$(find "$PIPELINE_ROOT/patches" -name "*.c" -type f 2>/dev/null | wc -l | tr -d ' ')
    MODEL_COUNT=$(find "$PIPELINE_ROOT/patches" -mindepth 1 -maxdepth 1 -type d ! -name ".*" 2>/dev/null | wc -l | tr -d ' ')
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
if [ -f "$PIPELINE_ROOT/reporter.py" ]; then
    echo -e "${GREEN}✓${NC} Found"
else
    echo -e "${RED}✗ Not found${NC}"
    ERRORS=$((ERRORS + 1))
fi

# Check reports directory
echo -n "Checking reports directory... "
if [ -d "$PIPELINE_ROOT/reports" ]; then
    REPORT_COUNT=$(find "$PIPELINE_ROOT/reports" -name "*.md" -type f 2>/dev/null | wc -l | tr -d ' ')
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
if [ -f "$PIPELINE_ROOT/pipeline.py" ]; then
    echo -e "${GREEN}✓${NC} Found"
else
    echo -e "${RED}✗ Not found${NC}"
    ERRORS=$((ERRORS + 1))
fi

# Check cleanup.py
echo -n "Checking cleanup.py... "
if [ -f "$PIPELINE_ROOT/cleanup.py" ]; then
    echo -e "${GREEN}✓${NC} Found"
else
    echo -e "${YELLOW}⚠${NC} Not found (optional utility)"
    WARNINGS=$((WARNINGS + 1))
fi

echo ""
echo -e "${BLUE}--- System Resources ---${NC}"

# Check disk space
echo -n "Checking available disk space... "
AVAILABLE=$(df -BG "$PIPELINE_ROOT" | tail -1 | awk '{print $4}' | sed 's/G//')
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
    echo "Run 'sudo ./setup/setup.sh' to install missing dependencies."
fi

echo "============================================="
echo ""

exit $ERRORS
