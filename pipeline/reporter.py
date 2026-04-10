#!/usr/bin/env python3
"""
AI-SSD Phase 4: Automated Reporting Pipeline

This script parses JSON outputs from Phases 1-3 and generates:
- Comprehensive Markdown reports
- Matplotlib visualizations comparing model performance
- SAST analysis summaries

Author: AI-SSD Project
Date: 2026-01-04
"""

import json
import os
import sys
import logging
import argparse
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from collections import defaultdict

# Matplotlib configuration (set backend before importing pyplot)
import matplotlib
matplotlib.use('Agg')  # Non-interactive backend for server environments
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np

# =============================================================================
# Configuration – loaded from config.yaml
# =============================================================================

BASE_DIR = Path(__file__).parent.resolve()

sys.path.insert(0, str(BASE_DIR))
from master_pipeline.config import load_pipeline_config  # noqa: E402

_cfg = load_pipeline_config(BASE_DIR)
_paths = _cfg.get("paths", {}) if isinstance(_cfg.get("paths"), dict) else {}

RESULTS_DIR = BASE_DIR / str(_paths.get("results", "results"))
PATCHES_DIR = BASE_DIR / str(_paths.get("patches", "patches"))
VALIDATION_RESULTS_DIR = BASE_DIR / str(_paths.get("validation_results", "validation_results"))
REPORTS_DIR = BASE_DIR / str(_paths.get("reports", "reports"))
LOG_DIR = BASE_DIR / str(_paths.get("logs", "logs"))

# Color scheme for visualizations
COLORS = {
    'success': '#2ecc71',      # Green
    'failure': '#e74c3c',      # Red
    'warning': '#f39c12',      # Orange
    'info': '#3498db',         # Blue
    'neutral': '#95a5a6',      # Gray
    'models': ['#3498db', '#9b59b6', '#1abc9c', '#e67e22']  # Blue, Purple, Teal, Orange
}

# =============================================================================
# Logging Setup
# =============================================================================

def setup_logging(verbose: bool = False) -> logging.Logger:
    """Configure logging for the reporter."""
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    
    logger = logging.getLogger('reporter')
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    
    # Clear existing handlers
    logger.handlers.clear()
    
    # Console handler
    console = logging.StreamHandler()
    console.setLevel(logging.DEBUG if verbose else logging.INFO)
    console.setFormatter(logging.Formatter(
        '%(asctime)s [%(levelname)s] %(message)s',
        datefmt='%H:%M:%S'
    ))
    logger.addHandler(console)
    
    # File handler
    file_handler = logging.FileHandler(
        LOG_DIR / f'reporter_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s [%(levelname)s] %(message)s'
    ))
    logger.addHandler(file_handler)
    
    return logger

logger = setup_logging()

# =============================================================================
# Data Classes
# =============================================================================

@dataclass
class Phase1Result:
    """Data from Phase 1: Vulnerability Reproduction"""
    cve: str
    commit_hash: str
    status: str
    vulnerability_reproduced: bool
    build_success: bool
    poc_executed: bool
    execution_time_seconds: float
    error_message: Optional[str]
    container_logs: str
    timestamp: str

@dataclass
class Phase2Result:
    """Data from Phase 2: Patch Generation"""
    cve_id: str
    function_name: str
    model: str
    success: bool
    syntax_valid: bool
    output_path: str

@dataclass
class SASTFinding:
    """SAST tool finding"""
    tool: str
    success: bool
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    findings_count: int
    error: Optional[str]

@dataclass
class Phase3Result:
    """Data from Phase 3: Patch Validation"""
    cve_id: str
    model_name: str
    status: str
    poc_blocked: bool
    build_success: bool
    sast_passed: bool
    sast_results: List[SASTFinding]
    poc_exit_code: int
    poc_output: str
    error_message: Optional[str]
    execution_time_seconds: float
    timestamp: str
    patch_file: str

@dataclass
class ModelStats:
    """Aggregated statistics per model"""
    model_name: str
    total_patches: int = 0
    syntax_valid: int = 0
    build_success: int = 0
    poc_blocked: int = 0
    sast_passed: int = 0
    total_sast_findings: int = 0
    critical_findings: int = 0
    high_findings: int = 0
    medium_findings: int = 0
    low_findings: int = 0
    avg_execution_time: float = 0.0

@dataclass
class CVEStats:
    """Aggregated statistics per CVE"""
    cve_id: str
    reproduced: bool = False
    total_patches: int = 0
    valid_patches: int = 0
    successful_fixes: int = 0
    best_model: Optional[str] = None


@dataclass
class FeedbackLoopAttempt:
    """Single feedback loop attempt"""
    attempt_number: int
    validation_passed: bool
    poc_blocked: bool
    sast_passed: bool
    build_success: bool
    failure_reasons: List[str]
    timestamp: str  # Legacy: end timestamp (kept for backwards compatibility)
    start_time: str = ""  # New: attempt start time
    end_time: str = ""  # New: attempt end time
    duration_seconds: float = 0.0  # New: attempt duration
    generation_duration_seconds: float = 0.0  # New: patch generation duration
    validation_duration_seconds: float = 0.0  # New: validation duration


@dataclass
class FeedbackLoopEntry:
    """Feedback loop result for a single CVE/model combination"""
    cve_id: str
    model_name: str
    final_status: str  # "success", "failed", "unpatchable"
    total_attempts: int
    max_retries: int
    attempts: List[FeedbackLoopAttempt]
    successful_on_attempt: Optional[int]
    final_patch_path: Optional[str]
    start_time: str = ""  # New: entry start time
    end_time: str = ""  # New: entry end time
    total_duration_seconds: float = 0.0  # New: total duration


@dataclass
class FeedbackLoopStats:
    """Aggregated feedback loop statistics"""
    total_entries: int = 0
    succeeded_first_try: int = 0
    succeeded_after_retry: int = 0
    marked_unpatchable: int = 0
    total_retry_attempts: int = 0
    avg_attempts_to_success: float = 0.0
    retry_success_rate: float = 0.0
    best_model: Optional[str] = None

# =============================================================================
# Data Loading
# =============================================================================

class DataLoader:
    """Loads and parses data from all phases."""
    
    def __init__(self, base_dir: Path):
        self.base_dir = base_dir
        _p = _paths  # use module-level config
        self.results_dir = base_dir / str(_p.get("results", "results"))
        self.patches_dir = base_dir / str(_p.get("patches", "patches"))
        self.validation_dir = base_dir / str(_p.get("validation_results", "validation_results"))
    
    def load_phase1_results(self) -> List[Phase1Result]:
        """Load Phase 1 vulnerability reproduction results."""
        results_file = self.results_dir / "results.json"
        
        if not results_file.exists():
            logger.warning(f"Phase 1 results not found: {results_file}")
            return []
        
        try:
            with open(results_file, 'r') as f:
                data = json.load(f)
            
            results = []
            for item in data.get('results', []):
                results.append(Phase1Result(
                    cve=item.get('cve', ''),
                    commit_hash=item.get('commit_hash', ''),
                    status=item.get('status', ''),
                    vulnerability_reproduced=item.get('vulnerability_reproduced', False),
                    build_success=item.get('build_success', False),
                    poc_executed=item.get('poc_executed', False),
                    execution_time_seconds=item.get('execution_time_seconds', 0),
                    error_message=item.get('error_message'),
                    container_logs=item.get('container_logs', ''),
                    timestamp=item.get('timestamp', '')
                ))
            
            logger.info(f"Loaded {len(results)} Phase 1 results")
            return results
            
        except Exception as e:
            logger.error(f"Error loading Phase 1 results: {e}")
            return []
    
    def load_phase2_results(self) -> Tuple[Dict[str, Any], List[Phase2Result]]:
        """Load Phase 2 patch generation results."""
        summary_file = self.patches_dir / "pipeline_summary.json"
        
        if not summary_file.exists():
            logger.warning(f"Phase 2 summary not found: {summary_file}")
            return {}, []
        
        try:
            with open(summary_file, 'r') as f:
                data = json.load(f)
            
            metadata = {
                'phase': data.get('metadata', {}).get('phase', 'Phase 2 - Patch Generation'),
                'generated_at': data.get('metadata', {}).get('generated_at', ''),
                # Support both old format and new format
                'start_time': data.get('phase_timing', {}).get('start_time') or data.get('start_time', ''),
                'end_time': data.get('phase_timing', {}).get('end_time') or data.get('end_time', ''),
                'duration_seconds': data.get('phase_timing', {}).get('total_duration_seconds') or data.get('duration_seconds', 0),
                'total_tasks': data.get('summary', {}).get('total_tasks') or data.get('total_tasks', 0),
                'successful': data.get('summary', {}).get('successful') or data.get('successful', 0),
                'syntax_valid': data.get('summary', {}).get('syntax_valid') or data.get('syntax_valid', 0),
                'failed': data.get('summary', {}).get('failed') or data.get('failed', 0),
                'total_prompt_tokens': data.get('summary', {}).get('total_prompt_tokens') or data.get('total_prompt_tokens', 0),
                'total_response_tokens': data.get('summary', {}).get('total_response_tokens') or data.get('total_response_tokens', 0),
                'total_llm_runtime_seconds': data.get('summary', {}).get('total_llm_runtime_seconds') or data.get('total_llm_runtime_seconds', 0),
            }
            
            results = []
            for item in data.get('results', []):
                results.append(Phase2Result(
                    cve_id=item.get('cve_id', ''),
                    function_name=item.get('function_name', ''),
                    model=item.get('model', ''),
                    success=item.get('success', False),
                    syntax_valid=item.get('syntax_valid', False),
                    output_path=item.get('output_path', '')
                ))
            
            logger.info(f"Loaded {len(results)} Phase 2 results")
            return metadata, results
            
        except Exception as e:
            logger.error(f"Error loading Phase 2 results: {e}")
            return {}, []
    
    def load_phase3_results(self) -> Tuple[Dict[str, Any], List[Phase3Result]]:
        """Load Phase 3 validation results."""
        # Find the most recent validation summary
        summary_files = list(self.validation_dir.glob("validation_summary_*.json"))
        
        if not summary_files:
            logger.warning("No Phase 3 validation summary found")
            return {}, []
        
        # Use the most recent summary
        summary_file = max(summary_files, key=lambda p: p.stat().st_mtime)
        
        try:
            with open(summary_file, 'r') as f:
                data = json.load(f)
            
            metadata = data.get('metadata', {})
            summary = data.get('summary', {})
            phase_timing = data.get('phase_timing', {})
            
            # Merge metadata with timing information
            metadata.update(summary)
            metadata['start_time'] = phase_timing.get('start_time', '')
            metadata['end_time'] = phase_timing.get('end_time', '')
            metadata['total_duration_seconds'] = phase_timing.get('total_duration_seconds', 0)
            metadata['total_execution_time_seconds'] = summary.get('total_execution_time_seconds', 0)
            
            results = []
            by_cve = data.get('by_cve', {})
            
            for cve_id, validations in by_cve.items():
                for item in validations:
                    sast_results = []
                    for sast in item.get('sast_results', []):
                        sast_results.append(SASTFinding(
                            tool=sast.get('tool', ''),
                            success=sast.get('success', False),
                            critical_count=sast.get('critical_count', 0),
                            high_count=sast.get('high_count', 0),
                            medium_count=sast.get('medium_count', 0),
                            low_count=sast.get('low_count', 0),
                            findings_count=sast.get('findings_count', 0),
                            error=sast.get('error')
                        ))
                    
                    results.append(Phase3Result(
                        cve_id=item.get('cve_id', cve_id),
                        model_name=item.get('model_name', ''),
                        status=item.get('status', ''),
                        poc_blocked=item.get('poc_blocked', False),
                        build_success=item.get('build_success', False),
                        sast_passed=item.get('sast_passed', False),
                        sast_results=sast_results,
                        poc_exit_code=item.get('poc_exit_code', -1),
                        poc_output=item.get('poc_output', ''),
                        error_message=item.get('error_message'),
                        execution_time_seconds=item.get('execution_time_seconds', 0),
                        timestamp=item.get('timestamp', ''),
                        patch_file=item.get('patch_file', '')
                    ))
            
            logger.info(f"Loaded {len(results)} Phase 3 results")
            return metadata, results
            
        except Exception as e:
            logger.error(f"Error loading Phase 3 results: {e}")
            return {}, []

    def load_feedback_loop_results(self) -> Tuple[Dict[str, Any], List[FeedbackLoopEntry]]:
        """Load feedback loop results from JSON files."""
        # Check both possible locations for feedback loop results:
        # 1. results/ directory (where pipeline.py saves them)
        # 2. feedback_loop_results/ directory (legacy location)
        results_dir = self.base_dir / "results"
        feedback_dir = self.base_dir / "feedback_loop_results"
        
        result_files = []
        
        # First check the results directory (primary location)
        if results_dir.exists():
            result_files.extend(list(results_dir.glob("feedback_loop_results_*.json")))
        
        # Also check legacy feedback_loop_results directory
        if feedback_dir.exists():
            result_files.extend(list(feedback_dir.glob("feedback_loop_*.json")))
        
        if not result_files:
            logger.info("No feedback loop results files found")
            return {}, []
        
        if not result_files:
            logger.info("No feedback loop results files found")
            return {}, []
        
        # Use the most recent file
        result_file = max(result_files, key=lambda p: p.stat().st_mtime)
        
        try:
            with open(result_file, 'r') as f:
                data = json.load(f)
            
            metadata = data.get('metadata', {})
            # Support old format without metadata section
            if not metadata:
                metadata = {
                    'timestamp': data.get('timestamp', ''),
                    'max_retries': data.get('max_retries', 3),
                }
            
            entries = []
            
            for item in data.get('results', []):
                attempts = []
                # Support both 'attempts' (new) and 'validation_history' (old) field names
                attempt_list = item.get('attempts', []) or item.get('validation_history', [])
                for attempt_data in attempt_list:
                    # Map old field names to new ones
                    attempt_num = attempt_data.get('attempt_number') or attempt_data.get('attempt', 0)
                    validation_passed = attempt_data.get('validation_passed', False)
                    # In old format, check if status is "Success"
                    if not validation_passed and attempt_data.get('status') == 'Success':
                        validation_passed = True
                    
                    attempts.append(FeedbackLoopAttempt(
                        attempt_number=attempt_num,
                        validation_passed=validation_passed,
                        poc_blocked=attempt_data.get('poc_blocked', False),
                        sast_passed=attempt_data.get('sast_passed', False),
                        build_success=attempt_data.get('build_success', True),  # Old format assumes build success if not specified
                        failure_reasons=attempt_data.get('failure_reasons', []) or ([attempt_data.get('error_message')] if attempt_data.get('error_message') else []),
                        timestamp=attempt_data.get('timestamp', ''),
                        # New timestamp fields (with backwards compatibility)
                        start_time=attempt_data.get('start_time', ''),
                        end_time=attempt_data.get('end_time', ''),
                        duration_seconds=attempt_data.get('duration_seconds', 0.0),
                        generation_duration_seconds=attempt_data.get('generation_duration_seconds', 0.0),
                        validation_duration_seconds=attempt_data.get('validation_duration_seconds', 0.0)
                    ))
                
                entries.append(FeedbackLoopEntry(
                    cve_id=item.get('cve_id', ''),
                    model_name=item.get('model_name', ''),
                    final_status=item.get('final_status', ''),
                    total_attempts=item.get('total_attempts', 0),
                    max_retries=item.get('max_retries', 3) or data.get('max_retries', 3),
                    attempts=attempts,
                    successful_on_attempt=item.get('successful_on_attempt') or item.get('successful_attempt'),
                    final_patch_path=item.get('final_patch_path'),
                    # New timing fields (with backwards compatibility)
                    start_time=item.get('start_time', ''),
                    end_time=item.get('end_time', ''),
                    total_duration_seconds=item.get('total_duration_seconds', 0.0)
                ))
            
            logger.info(f"Loaded {len(entries)} feedback loop entries")
            return metadata, entries
            
        except Exception as e:
            logger.error(f"Error loading feedback loop results: {e}")
            return {}, []

# =============================================================================
# Statistics Calculator
# =============================================================================

class StatsCalculator:
    """Calculates aggregate statistics from phase results."""
    
    def __init__(
        self,
        phase1_results: List[Phase1Result],
        phase2_results: List[Phase2Result],
        phase3_results: List[Phase3Result]
    ):
        self.phase1 = phase1_results
        self.phase2 = phase2_results
        self.phase3 = phase3_results
    
    def get_model_stats(self) -> Dict[str, ModelStats]:
        """Calculate per-model statistics."""
        stats: Dict[str, ModelStats] = {}
        
        # Initialize from Phase 2 results
        for r in self.phase2:
            model = self._normalize_model_name(r.model)
            if model not in stats:
                stats[model] = ModelStats(model_name=model)
            
            stats[model].total_patches += 1
            if r.syntax_valid:
                stats[model].syntax_valid += 1
        
        # Add Phase 3 validation stats
        execution_times: Dict[str, List[float]] = defaultdict(list)
        
        for r in self.phase3:
            model = self._normalize_model_name(r.model_name)
            if model not in stats:
                stats[model] = ModelStats(model_name=model)
            
            if r.build_success:
                stats[model].build_success += 1
            if r.poc_blocked:
                stats[model].poc_blocked += 1
            if r.sast_passed:
                stats[model].sast_passed += 1
            
            # Aggregate SAST findings
            for sast in r.sast_results:
                stats[model].total_sast_findings += sast.findings_count
                stats[model].critical_findings += sast.critical_count
                stats[model].high_findings += sast.high_count
                stats[model].medium_findings += sast.medium_count
                stats[model].low_findings += sast.low_count
            
            execution_times[model].append(r.execution_time_seconds)
        
        # Calculate average execution times
        for model, times in execution_times.items():
            if times and model in stats:
                stats[model].avg_execution_time = sum(times) / len(times)
        
        return stats
    
    def get_cve_stats(self) -> Dict[str, CVEStats]:
        """Calculate per-CVE statistics."""
        stats: Dict[str, CVEStats] = {}
        
        # Initialize from Phase 1 results
        for r in self.phase1:
            if r.cve not in stats:
                stats[r.cve] = CVEStats(cve_id=r.cve)
            stats[r.cve].reproduced = r.vulnerability_reproduced
        
        # Add Phase 2 results
        for r in self.phase2:
            if r.cve_id not in stats:
                stats[r.cve_id] = CVEStats(cve_id=r.cve_id)
            stats[r.cve_id].total_patches += 1
            if r.syntax_valid:
                stats[r.cve_id].valid_patches += 1
        
        # Add Phase 3 results and find best model
        model_successes: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
        
        for r in self.phase3:
            if r.cve_id not in stats:
                stats[r.cve_id] = CVEStats(cve_id=r.cve_id)
            
            if r.poc_blocked and r.sast_passed:
                stats[r.cve_id].successful_fixes += 1
                model = self._normalize_model_name(r.model_name)
                model_successes[r.cve_id][model] += 1
        
        # Determine best model per CVE
        for cve_id, models in model_successes.items():
            if models and cve_id in stats:
                stats[cve_id].best_model = max(models.keys(), key=lambda m: models[m])
        
        return stats
    
    def get_sast_summary(self) -> Dict[str, Dict[str, int]]:
        """Get SAST tool summary across all validations."""
        summary: Dict[str, Dict[str, int]] = defaultdict(lambda: {
            'total_runs': 0,
            'successful_runs': 0,
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'total_findings': 0
        })
        
        for r in self.phase3:
            for sast in r.sast_results:
                tool = sast.tool
                summary[tool]['total_runs'] += 1
                if sast.success:
                    summary[tool]['successful_runs'] += 1
                summary[tool]['critical'] += sast.critical_count
                summary[tool]['high'] += sast.high_count
                summary[tool]['medium'] += sast.medium_count
                summary[tool]['low'] += sast.low_count
                summary[tool]['total_findings'] += sast.findings_count
        
        return dict(summary)
    
    @staticmethod
    def get_feedback_loop_stats(entries: List[FeedbackLoopEntry]) -> FeedbackLoopStats:
        """Calculate feedback loop statistics."""
        stats = FeedbackLoopStats()
        
        if not entries:
            return stats
        
        stats.total_entries = len(entries)
        successful_attempts = []
        
        for entry in entries:
            if entry.final_status == "success":
                if entry.successful_on_attempt == 1:
                    stats.succeeded_first_try += 1
                else:
                    stats.succeeded_after_retry += 1
                if entry.successful_on_attempt:
                    successful_attempts.append(entry.successful_on_attempt)
            elif entry.final_status == "unpatchable":
                stats.marked_unpatchable += 1
            
            # Count total retry attempts (attempts beyond the first)
            if entry.total_attempts > 1:
                stats.total_retry_attempts += entry.total_attempts - 1
        
        # Calculate averages
        if successful_attempts:
            stats.avg_attempts_to_success = sum(successful_attempts) / len(successful_attempts)
        
        # Calculate retry success rate (successes after retry / total entries that needed retry)
        entries_needing_retry = stats.succeeded_after_retry + stats.marked_unpatchable
        if entries_needing_retry > 0:
            stats.retry_success_rate = (stats.succeeded_after_retry / entries_needing_retry) * 100
        
        return stats
    
    def _normalize_model_name(self, name: str) -> str:
        """Normalize model name for consistent comparison."""
        # Handle different naming conventions
        name = name.replace(':', '_').replace('-', '_').replace('.', '_')
        return name.lower()

# =============================================================================
# Visualization Generator
# =============================================================================

class VisualizationGenerator:
    """Generates Matplotlib visualizations."""
    
    def __init__(self, output_dir: Path):
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Set style
        plt.style.use('seaborn-v0_8-whitegrid')
        plt.rcParams['figure.figsize'] = (12, 8)
        plt.rcParams['font.size'] = 12
        plt.rcParams['axes.titlesize'] = 14
        plt.rcParams['axes.labelsize'] = 12
    
    def generate_model_comparison_chart(
        self,
        model_stats: Dict[str, ModelStats],
        phase2_results: List[Phase2Result]
    ) -> Path:
        """Generate bar chart comparing model success rates."""
        fig, ax = plt.subplots(figsize=(14, 8))
        
        models = list(model_stats.keys())
        x = np.arange(len(models))
        width = 0.25
        
        # Calculate percentages
        syntax_valid_pct = []
        vuln_fixed_pct = []
        sast_passed_pct = []
        
        for model in models:
            stats = model_stats[model]
            total = stats.total_patches if stats.total_patches > 0 else 1
            
            syntax_valid_pct.append((stats.syntax_valid / total) * 100)
            vuln_fixed_pct.append((stats.poc_blocked / total) * 100 if stats.poc_blocked else 0)
            sast_passed_pct.append((stats.sast_passed / total) * 100 if stats.sast_passed else 0)
        
        # Create bars
        bars1 = ax.bar(x - width, syntax_valid_pct, width, label='Syntax Valid %', 
                       color=COLORS['info'], edgecolor='black', linewidth=0.5)
        bars2 = ax.bar(x, vuln_fixed_pct, width, label='Vulnerability Fixed %', 
                       color=COLORS['success'], edgecolor='black', linewidth=0.5)
        bars3 = ax.bar(x + width, sast_passed_pct, width, label='SAST Passed %', 
                       color=COLORS['models'][2], edgecolor='black', linewidth=0.5)
        
        # Labels and formatting
        ax.set_xlabel('Model')
        ax.set_ylabel('Success Rate (%)')
        ax.set_title('AI-SSD: Model Performance Comparison\n(Syntax Validation vs. Vulnerability Fix vs. SAST Analysis)')
        ax.set_xticks(x)
        ax.set_xticklabels([self._format_model_name(m) for m in models], rotation=15, ha='right')
        ax.legend(loc='upper right')
        ax.set_ylim(0, 110)
        
        # Add value labels on bars
        for bars in [bars1, bars2, bars3]:
            for bar in bars:
                height = bar.get_height()
                if height > 0:
                    ax.annotate(f'{height:.1f}%',
                                xy=(bar.get_x() + bar.get_width() / 2, height),
                                xytext=(0, 3),
                                textcoords="offset points",
                                ha='center', va='bottom', fontsize=9)
        
        plt.tight_layout()
        
        output_path = self.output_dir / "model_comparison.png"
        plt.savefig(output_path, dpi=150, bbox_inches='tight')
        plt.close()
        
        logger.info(f"Generated model comparison chart: {output_path}")
        return output_path
    
    def generate_sast_findings_chart(self, sast_summary: Dict[str, Dict[str, int]]) -> Path:
        """Generate stacked bar chart of SAST findings by severity."""
        fig, ax = plt.subplots(figsize=(12, 7))
        
        tools = list(sast_summary.keys())
        x = np.arange(len(tools))
        width = 0.6
        
        critical = [sast_summary[t]['critical'] for t in tools]
        high = [sast_summary[t]['high'] for t in tools]
        medium = [sast_summary[t]['medium'] for t in tools]
        low = [sast_summary[t]['low'] for t in tools]
        
        # Create stacked bars
        bars1 = ax.bar(x, critical, width, label='Critical', color='#c0392b')
        bars2 = ax.bar(x, high, width, bottom=critical, label='High', color='#e74c3c')
        bars3 = ax.bar(x, medium, width, bottom=np.array(critical) + np.array(high), 
                       label='Medium', color='#f39c12')
        bars4 = ax.bar(x, low, width, 
                       bottom=np.array(critical) + np.array(high) + np.array(medium),
                       label='Low', color='#f1c40f')
        
        ax.set_xlabel('SAST Tool')
        ax.set_ylabel('Number of Findings')
        ax.set_title('AI-SSD: SAST Findings by Tool and Severity')
        ax.set_xticks(x)
        ax.set_xticklabels([t.capitalize() for t in tools])
        ax.legend(loc='upper right')
        
        # Add total labels
        totals = [sum(x) for x in zip(critical, high, medium, low)]
        for i, total in enumerate(totals):
            if total > 0:
                ax.annotate(f'Total: {total}',
                            xy=(i, total),
                            xytext=(0, 5),
                            textcoords="offset points",
                            ha='center', fontsize=10, fontweight='bold')
        
        plt.tight_layout()
        
        output_path = self.output_dir / "sast_findings.png"
        plt.savefig(output_path, dpi=150, bbox_inches='tight')
        plt.close()
        
        logger.info(f"Generated SAST findings chart: {output_path}")
        return output_path
    
    def generate_cve_success_chart(self, cve_stats: Dict[str, CVEStats]) -> Path:
        """Generate pie chart showing CVE fix success distribution."""
        fig, axes = plt.subplots(1, 2, figsize=(14, 6))
        
        # Left: Overall success rate
        total_cves = len(cve_stats)
        fixed_cves = sum(1 for s in cve_stats.values() if s.successful_fixes > 0)
        unfixed_cves = total_cves - fixed_cves
        
        if total_cves > 0:
            sizes = [fixed_cves, unfixed_cves]
            labels = [f'Fixed ({fixed_cves})', f'Not Fixed ({unfixed_cves})']
            colors = [COLORS['success'], COLORS['failure']]
            
            axes[0].pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%',
                       startangle=90, explode=(0.05, 0))
            axes[0].set_title('CVE Fix Success Rate')
        
        # Right: Patches per CVE
        cves = list(cve_stats.keys())
        total_patches = [cve_stats[c].total_patches for c in cves]
        successful_fixes = [cve_stats[c].successful_fixes for c in cves]
        
        x = np.arange(len(cves))
        width = 0.35
        
        axes[1].bar(x - width/2, total_patches, width, label='Total Patches', 
                    color=COLORS['info'])
        axes[1].bar(x + width/2, successful_fixes, width, label='Successful Fixes', 
                    color=COLORS['success'])
        
        axes[1].set_xlabel('CVE')
        axes[1].set_ylabel('Count')
        axes[1].set_title('Patches Generated vs. Successful Fixes per CVE')
        axes[1].set_xticks(x)
        axes[1].set_xticklabels(cves, rotation=15, ha='right')
        axes[1].legend()
        
        plt.tight_layout()
        
        output_path = self.output_dir / "cve_success.png"
        plt.savefig(output_path, dpi=150, bbox_inches='tight')
        plt.close()
        
        logger.info(f"Generated CVE success chart: {output_path}")
        return output_path
    
    def generate_execution_time_chart(self, model_stats: Dict[str, ModelStats]) -> Path:
        """Generate bar chart of average execution times per model."""
        fig, ax = plt.subplots(figsize=(10, 6))
        
        models = list(model_stats.keys())
        times = [model_stats[m].avg_execution_time for m in models]
        
        colors = [COLORS['models'][i % len(COLORS['models'])] for i in range(len(models))]
        
        bars = ax.barh(models, times, color=colors, edgecolor='black', linewidth=0.5)
        
        ax.set_xlabel('Average Execution Time (seconds)')
        ax.set_ylabel('Model')
        ax.set_title('AI-SSD: Average Validation Time per Model')
        
        # Add value labels
        for bar, time in zip(bars, times):
            if time > 0:
                ax.annotate(f'{time:.1f}s',
                            xy=(time, bar.get_y() + bar.get_height()/2),
                            xytext=(5, 0),
                            textcoords="offset points",
                            ha='left', va='center', fontsize=10)
        
        plt.tight_layout()
        
        output_path = self.output_dir / "execution_times.png"
        plt.savefig(output_path, dpi=150, bbox_inches='tight')
        plt.close()
        
        logger.info(f"Generated execution time chart: {output_path}")
        return output_path
    
    def generate_pipeline_summary_chart(
        self,
        phase1_results: List[Phase1Result],
        phase2_metadata: Dict[str, Any],
        phase3_metadata: Dict[str, Any]
    ) -> Path:
        """Generate overview chart of pipeline phases."""
        fig, ax = plt.subplots(figsize=(12, 6))
        
        phases = ['Phase 1:\nReproduction', 'Phase 2:\nPatch Gen', 'Phase 3:\nValidation']
        
        # Calculate success metrics for each phase
        p1_success = sum(1 for r in phase1_results if r.vulnerability_reproduced)
        p1_total = len(phase1_results) or 1
        
        p2_success = phase2_metadata.get('syntax_valid', 0)
        p2_total = phase2_metadata.get('total_tasks', 0) or 1
        
        p3_success = phase3_metadata.get('poc_blocked', 0)
        p3_total = phase3_metadata.get('total_validations', 0) or 1
        
        success_rates = [
            (p1_success / p1_total) * 100,
            (p2_success / p2_total) * 100,
            (p3_success / p3_total) * 100
        ]
        
        x = np.arange(len(phases))
        colors = [COLORS['success'] if r >= 50 else COLORS['warning'] for r in success_rates]
        
        bars = ax.bar(x, success_rates, color=colors, edgecolor='black', linewidth=1)
        
        ax.set_xlabel('Pipeline Phase')
        ax.set_ylabel('Success Rate (%)')
        ax.set_title('AI-SSD: Pipeline Phase Success Overview')
        ax.set_xticks(x)
        ax.set_xticklabels(phases)
        ax.set_ylim(0, 110)
        
        # Add annotations
        annotations = [
            f'{p1_success}/{p1_total}\nCVEs Reproduced',
            f'{p2_success}/{p2_total}\nSyntax Valid',
            f'{p3_success}/{p3_total}\nVuln Fixed'
        ]
        
        for bar, rate, annot in zip(bars, success_rates, annotations):
            ax.annotate(f'{rate:.1f}%\n{annot}',
                        xy=(bar.get_x() + bar.get_width()/2, bar.get_height()),
                        xytext=(0, 5),
                        textcoords="offset points",
                        ha='center', va='bottom', fontsize=10)
        
        plt.tight_layout()
        
        output_path = self.output_dir / "pipeline_overview.png"
        plt.savefig(output_path, dpi=150, bbox_inches='tight')
        plt.close()
        
        logger.info(f"Generated pipeline overview chart: {output_path}")
        return output_path
    
    def _format_model_name(self, name: str) -> str:
        """Format model name for display."""
        # Convert normalized name back to readable format
        parts = name.split('_')
        if len(parts) >= 2:
            return f"{parts[0]}-{'.'.join(parts[1:])}"
        return name

# =============================================================================
# Report Generator
# =============================================================================

class ReportGenerator:
    """Generates Markdown reports from analysis results."""
    
    def __init__(self, output_dir: Path):
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def generate_full_report(
        self,
        phase1_results: List[Phase1Result],
        phase2_metadata: Dict[str, Any],
        phase2_results: List[Phase2Result],
        phase3_metadata: Dict[str, Any],
        phase3_results: List[Phase3Result],
        model_stats: Dict[str, ModelStats],
        cve_stats: Dict[str, CVEStats],
        sast_summary: Dict[str, Dict[str, int]],
        chart_paths: Dict[str, Path],
        feedback_entries: Optional[List[FeedbackLoopEntry]] = None,
        feedback_stats: Optional[FeedbackLoopStats] = None
    ) -> Path:
        """Generate comprehensive Markdown report."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        report = []
        report.append("# AI-SSD Pipeline Report")
        report.append(f"\n**Generated:** {timestamp}")
        report.append("\n---\n")
        
        # Executive Summary
        report.append("## Executive Summary\n")
        report.append(self._generate_executive_summary(
            phase1_results, phase2_metadata, phase3_metadata, model_stats, cve_stats
        ))
        
        # Pipeline Overview
        if 'pipeline_overview' in chart_paths:
            report.append("\n### Pipeline Success Overview\n")
            report.append(f"![Pipeline Overview]({chart_paths['pipeline_overview'].name})\n")
        
        # Phase 1 Results
        report.append("\n---\n")
        report.append("## Phase 1: Vulnerability Reproduction\n")
        report.append(self._generate_phase1_section(phase1_results))
        
        # Phase 2 Results
        report.append("\n---\n")
        report.append("## Phase 2: Patch Generation\n")
        report.append(self._generate_phase2_section(phase2_metadata, phase2_results))
        
        # Phase 3 Results
        report.append("\n---\n")
        report.append("## Phase 3: Patch Validation\n")
        report.append(self._generate_phase3_section(phase3_metadata, phase3_results))
        
        # Model Performance Analysis
        report.append("\n---\n")
        report.append("## Model Performance Analysis\n")
        report.append(self._generate_model_analysis(model_stats))
        
        if 'model_comparison' in chart_paths:
            report.append(f"\n![Model Comparison]({chart_paths['model_comparison'].name})\n")
        
        if 'execution_times' in chart_paths:
            report.append(f"\n![Execution Times]({chart_paths['execution_times'].name})\n")
        
        # SAST Analysis
        report.append("\n---\n")
        report.append("## SAST Analysis Summary\n")
        report.append(self._generate_sast_section(sast_summary))
        
        if 'sast_findings' in chart_paths:
            report.append(f"\n![SAST Findings]({chart_paths['sast_findings'].name})\n")
        
        # CVE Analysis
        report.append("\n---\n")
        report.append("## CVE-Specific Analysis\n")
        report.append(self._generate_cve_analysis(cve_stats, phase3_results))
        
        if 'cve_success' in chart_paths:
            report.append(f"\n![CVE Success]({chart_paths['cve_success'].name})\n")
        
        # Feedback Loop (Self-Healing) Section
        if feedback_entries is not None and feedback_stats is not None:
            report.append("\n---\n")
            report.append("## Iterative Feedback Loop (Self-Healing)\n")
            report.append(self._generate_feedback_loop_section(feedback_entries, feedback_stats))
        
        # Recommendations
        report.append("\n---\n")
        report.append("## Recommendations\n")
        report.append(self._generate_recommendations(model_stats, cve_stats, sast_summary))
        
        # Appendix
        report.append("\n---\n")
        report.append("## Appendix: Detailed Results\n")
        report.append(self._generate_appendix(phase3_results))
        
        # Write report
        output_path = self.output_dir / f"pipeline_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        with open(output_path, 'w') as f:
            f.write('\n'.join(report))
        
        logger.info(f"Generated report: {output_path}")
        return output_path
    
    def _generate_executive_summary(
        self,
        phase1_results: List[Phase1Result],
        phase2_metadata: Dict[str, Any],
        phase3_metadata: Dict[str, Any],
        model_stats: Dict[str, ModelStats],
        cve_stats: Dict[str, CVEStats]
    ) -> str:
        """Generate executive summary section."""
        lines = []
        
        # Overall metrics
        total_cves = len(cve_stats)
        reproduced = sum(1 for r in phase1_results if r.vulnerability_reproduced)
        total_patches = phase2_metadata.get('total_tasks', 0)
        syntax_valid = phase2_metadata.get('syntax_valid', 0)
        vulnerabilities_fixed = sum(s.successful_fixes for s in cve_stats.values())
        
        lines.append("| Metric | Value |")
        lines.append("|--------|-------|")
        lines.append(f"| CVEs Analyzed | {total_cves} |")
        lines.append(f"| Vulnerabilities Reproduced | {reproduced}/{total_cves} ({reproduced/total_cves*100:.1f}%) |")
        lines.append(f"| Total Patches Generated | {total_patches} |")
        lines.append(f"| Syntax Valid Patches | {syntax_valid}/{total_patches} ({syntax_valid/total_patches*100 if total_patches else 0:.1f}%) |")
        lines.append(f"| Successful Vulnerability Fixes | {vulnerabilities_fixed} |")
        
        # Best performing model
        if model_stats:
            best_model = max(model_stats.values(), 
                           key=lambda s: s.poc_blocked / s.total_patches if s.total_patches else 0)
            lines.append(f"| Best Performing Model | {best_model.model_name} |")
        
        lines.append("")
        
        # Key findings
        lines.append("### Key Findings\n")
        
        if vulnerabilities_fixed > 0:
            lines.append(f"- ✅ **{vulnerabilities_fixed}** patches successfully mitigated vulnerabilities")
        else:
            lines.append("- ⚠️ No patches successfully mitigated vulnerabilities in validation")
        
        syntax_rate = (syntax_valid / total_patches * 100) if total_patches else 0
        if syntax_rate >= 70:
            lines.append(f"- ✅ High syntax validity rate: **{syntax_rate:.1f}%**")
        else:
            lines.append(f"- ⚠️ Syntax validity rate needs improvement: **{syntax_rate:.1f}%**")
        
        return '\n'.join(lines)
    
    def _generate_phase1_section(self, results: List[Phase1Result]) -> str:
        """Generate Phase 1 section."""
        lines = []
        
        if not results:
            lines.append("*No Phase 1 results available.*")
            return '\n'.join(lines)
        
        lines.append("### Vulnerability Reproduction Results\n")
        lines.append("| CVE | Status | Build | PoC Executed | Time (s) |")
        lines.append("|-----|--------|-------|--------------|----------|")
        
        for r in results:
            status_icon = "✅" if r.vulnerability_reproduced else "❌"
            build_icon = "✅" if r.build_success else "❌"
            poc_icon = "✅" if r.poc_executed else "❌"
            lines.append(f"| {r.cve} | {status_icon} {r.status} | {build_icon} | {poc_icon} | {r.execution_time_seconds:.1f} |")
        
        return '\n'.join(lines)
    
    def _generate_phase2_section(
        self, 
        metadata: Dict[str, Any], 
        results: List[Phase2Result]
    ) -> str:
        """Generate Phase 2 section."""
        lines = []
        
        if not results:
            lines.append("*No Phase 2 results available.*")
            return '\n'.join(lines)
        
        lines.append("### Patch Generation Summary\n")
        lines.append(f"- **Duration:** {metadata.get('duration_seconds', 0):.1f} seconds")
        lines.append(f"- **Total Tasks:** {metadata.get('total_tasks', 0)}")
        lines.append(f"- **Successful:** {metadata.get('successful', 0)}")
        lines.append(f"- **Syntax Valid:** {metadata.get('syntax_valid', 0)}")
        lines.append(f"- **Failed:** {metadata.get('failed', 0)}")
        lines.append("")
        
        # Group by model
        by_model = defaultdict(list)
        for r in results:
            by_model[r.model].append(r)
        
        lines.append("### Results by Model\n")
        lines.append("| Model | Total | Syntax Valid | Success Rate |")
        lines.append("|-------|-------|--------------|--------------|")
        
        for model, model_results in sorted(by_model.items()):
            total = len(model_results)
            valid = sum(1 for r in model_results if r.syntax_valid)
            rate = (valid / total * 100) if total else 0
            lines.append(f"| {model} | {total} | {valid} | {rate:.1f}% |")
        
        return '\n'.join(lines)
    
    def _generate_phase3_section(
        self, 
        metadata: Dict[str, Any], 
        results: List[Phase3Result]
    ) -> str:
        """Generate Phase 3 section."""
        lines = []
        
        if not results:
            lines.append("*No Phase 3 results available.*")
            return '\n'.join(lines)
        
        lines.append("### Validation Summary\n")
        lines.append(f"- **Total Validations:** {metadata.get('total_validations', len(results))}")
        lines.append(f"- **Successful (PoC Blocked):** {metadata.get('poc_blocked', 0)}")
        lines.append(f"- **SAST Passed:** {metadata.get('sast_passed', 0)}")
        lines.append(f"- **Success Rate:** {metadata.get('success_rate', 'N/A')}")
        lines.append("")
        
        lines.append("### Detailed Results\n")
        lines.append("| CVE | Model | Status | PoC Blocked | SAST | Time (s) |")
        lines.append("|-----|-------|--------|-------------|------|----------|")
        
        for r in results:
            status_icon = "✅" if r.status == "Success" else "❌"
            poc_icon = "✅" if r.poc_blocked else "❌"
            sast_icon = "✅" if r.sast_passed else "❌"
            lines.append(f"| {r.cve_id} | {r.model_name} | {status_icon} | {poc_icon} | {sast_icon} | {r.execution_time_seconds:.1f} |")
        
        return '\n'.join(lines)
    
    def _generate_model_analysis(self, model_stats: Dict[str, ModelStats]) -> str:
        """Generate model analysis section."""
        lines = []
        
        if not model_stats:
            lines.append("*No model statistics available.*")
            return '\n'.join(lines)
        
        lines.append("### Model Performance Metrics\n")
        lines.append("| Model | Total | Syntax Valid | Build OK | PoC Blocked | SAST Passed | Avg Time |")
        lines.append("|-------|-------|--------------|----------|-------------|-------------|----------|")
        
        for model, stats in sorted(model_stats.items()):
            lines.append(
                f"| {model} | {stats.total_patches} | "
                f"{stats.syntax_valid} ({stats.syntax_valid/stats.total_patches*100 if stats.total_patches else 0:.0f}%) | "
                f"{stats.build_success} | "
                f"{stats.poc_blocked} | "
                f"{stats.sast_passed} | "
                f"{stats.avg_execution_time:.1f}s |"
            )
        
        return '\n'.join(lines)
    
    def _generate_sast_section(self, sast_summary: Dict[str, Dict[str, int]]) -> str:
        """Generate SAST analysis section."""
        lines = []
        
        if not sast_summary:
            lines.append("*No SAST results available.*")
            return '\n'.join(lines)
        
        lines.append("### SAST Tool Results\n")
        lines.append("| Tool | Runs | Critical | High | Medium | Low | Total |")
        lines.append("|------|------|----------|------|--------|-----|-------|")
        
        for tool, data in sorted(sast_summary.items()):
            lines.append(
                f"| {tool.capitalize()} | {data['total_runs']} | "
                f"{data['critical']} | {data['high']} | "
                f"{data['medium']} | {data['low']} | "
                f"{data['total_findings']} |"
            )
        
        # Highlight any critical/high findings
        total_critical = sum(d['critical'] for d in sast_summary.values())
        total_high = sum(d['high'] for d in sast_summary.values())
        
        if total_critical > 0:
            lines.append(f"\n⚠️ **Warning:** {total_critical} critical severity findings detected")
        if total_high > 0:
            lines.append(f"\n⚠️ **Warning:** {total_high} high severity findings detected")
        
        return '\n'.join(lines)
    
    def _generate_cve_analysis(
        self, 
        cve_stats: Dict[str, CVEStats],
        phase3_results: List[Phase3Result]
    ) -> str:
        """Generate CVE-specific analysis."""
        lines = []
        
        if not cve_stats:
            lines.append("*No CVE statistics available.*")
            return '\n'.join(lines)
        
        lines.append("### CVE Fix Summary\n")
        lines.append("| CVE | Reproduced | Patches | Valid | Fixed | Best Model |")
        lines.append("|-----|------------|---------|-------|-------|------------|")
        
        for cve_id, stats in sorted(cve_stats.items()):
            repro_icon = "✅" if stats.reproduced else "❌"
            best = stats.best_model or "N/A"
            lines.append(
                f"| {cve_id} | {repro_icon} | "
                f"{stats.total_patches} | {stats.valid_patches} | "
                f"{stats.successful_fixes} | {best} |"
            )
        
        return '\n'.join(lines)
    
    def _generate_feedback_loop_section(
        self,
        feedback_entries: List[FeedbackLoopEntry],
        feedback_stats: FeedbackLoopStats
    ) -> str:
        """Generate feedback loop (self-healing) section."""
        lines = []
        
        if not feedback_entries:
            lines.append("*No feedback loop results available. The feedback loop was either disabled or not triggered.*")
            return '\n'.join(lines)
        
        # Summary statistics
        lines.append("### Feedback Loop Summary\n")
        lines.append("The iterative feedback loop (self-healing mechanism) automatically retries failed patches "
                    "by providing failure context to the LLM for improved patch generation.\n")
        
        lines.append("| Metric | Value |")
        lines.append("|--------|-------|")
        lines.append(f"| Total Patches Processed | {feedback_stats.total_entries} |")
        lines.append(f"| Succeeded on First Try | {feedback_stats.succeeded_first_try} |")
        lines.append(f"| Succeeded After Retry | {feedback_stats.succeeded_after_retry} |")
        lines.append(f"| Marked as Unpatchable | {feedback_stats.marked_unpatchable} |")
        lines.append(f"| Total Retry Attempts | {feedback_stats.total_retry_attempts} |")
        lines.append(f"| Avg Attempts to Success | {feedback_stats.avg_attempts_to_success:.2f} |")
        lines.append(f"| Retry Success Rate | {feedback_stats.retry_success_rate:.1f}% |")
        lines.append("")
        
        # Effectiveness analysis
        lines.append("### Feedback Loop Effectiveness\n")
        
        if feedback_stats.succeeded_after_retry > 0:
            lines.append(f"✅ **{feedback_stats.succeeded_after_retry}** patches were successfully fixed "
                        f"through the self-healing mechanism that would have otherwise failed.")
        
        if feedback_stats.marked_unpatchable > 0:
            lines.append(f"⚠️ **{feedback_stats.marked_unpatchable}** patches were marked as **unpatchable** "
                        f"after exhausting all retry attempts. These require manual review.")
        
        lines.append("")
        
        # Detailed retry history
        lines.append("### Detailed Retry History\n")
        lines.append("| CVE | Model | Final Status | Attempts | Success On |")
        lines.append("|-----|-------|--------------|----------|------------|")
        
        for entry in feedback_entries:
            status_icon = "✅" if entry.final_status == "success" else ("⚠️" if entry.final_status == "unpatchable" else "❌")
            success_on = str(entry.successful_on_attempt) if entry.successful_on_attempt else "N/A"
            lines.append(f"| {entry.cve_id} | {entry.model_name} | {status_icon} {entry.final_status} | "
                        f"{entry.total_attempts}/{entry.max_retries + 1} | {success_on} |")
        
        lines.append("")
        
        # Show unpatchable entries with failure reasons
        unpatchable = [e for e in feedback_entries if e.final_status == "unpatchable"]
        if unpatchable:
            lines.append("### Unpatchable Entries - Failure Analysis\n")
            for entry in unpatchable:
                lines.append(f"#### {entry.cve_id} - {entry.model_name}\n")
                lines.append(f"- **Total Attempts:** {entry.total_attempts}")
                lines.append("- **Failure History:**")
                for attempt in entry.attempts:
                    reasons = ", ".join(attempt.failure_reasons) if attempt.failure_reasons else "Unknown"
                    lines.append(f"  - Attempt {attempt.attempt_number}: {reasons}")
                lines.append("")
        
        return '\n'.join(lines)
    
    def _generate_recommendations(
        self,
        model_stats: Dict[str, ModelStats],
        cve_stats: Dict[str, CVEStats],
        sast_summary: Dict[str, Dict[str, int]]
    ) -> str:
        """Generate recommendations section."""
        lines = []
        
        lines.append("Based on the analysis, here are the recommendations:\n")
        
        # Model recommendations
        if model_stats:
            best_model = max(model_stats.values(), 
                           key=lambda s: s.poc_blocked / s.total_patches if s.total_patches else 0)
            lines.append(f"1. **Best Model:** Use `{best_model.model_name}` for patch generation - "
                        f"it achieved the highest vulnerability fix rate.")
            
            worst_model = min(model_stats.values(), 
                            key=lambda s: s.syntax_valid / s.total_patches if s.total_patches else 1)
            if worst_model.syntax_valid / worst_model.total_patches < 0.5 if worst_model.total_patches else False:
                lines.append(f"2. **Consider Removing:** `{worst_model.model_name}` has low syntax validity - "
                            "consider fine-tuning or removing from pipeline.")
        
        # SAST recommendations
        total_critical = sum(d['critical'] for d in sast_summary.values())
        if total_critical > 0:
            lines.append(f"3. **Security Review:** Review {total_critical} critical SAST findings "
                        "before deploying any patches.")
        
        # CVE-specific recommendations
        unfixed_cves = [cve for cve, stats in cve_stats.items() if stats.successful_fixes == 0]
        if unfixed_cves:
            lines.append(f"4. **Manual Review Required:** CVEs {', '.join(unfixed_cves)} "
                        "have no successful patches - manual patching may be required.")
        
        # General recommendations
        lines.append("5. **Continuous Improvement:** Collect failed patches to fine-tune models.")
        lines.append("6. **Expand Testing:** Add more comprehensive test cases beyond PoC exploits.")
        
        return '\n'.join(lines)
    
    def _generate_appendix(self, phase3_results: List[Phase3Result]) -> str:
        """Generate appendix with detailed results."""
        lines = []
        
        lines.append("### Successful Patches\n")
        
        successful = [r for r in phase3_results if r.poc_blocked and r.sast_passed]
        
        if successful:
            for r in successful:
                lines.append(f"#### {r.cve_id} - {r.model_name}\n")
                lines.append(f"- **Patch File:** `{r.patch_file}`")
                lines.append(f"- **Execution Time:** {r.execution_time_seconds:.1f}s")
                lines.append(f"- **PoC Exit Code:** {r.poc_exit_code}")
                lines.append("")
        else:
            lines.append("*No fully successful patches (PoC blocked + SAST passed).*")
        
        return '\n'.join(lines)

# =============================================================================
# Main Reporter Class
# =============================================================================

class PipelineReporter:
    """Main class orchestrating report generation."""
    
    def __init__(self, base_dir: Path, output_dir: Optional[Path] = None):
        self.base_dir = base_dir
        self.output_dir = output_dir or (base_dir / str(_paths.get("reports", "reports")))
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        self.loader = DataLoader(base_dir)
        self.viz_gen = VisualizationGenerator(self.output_dir)
        self.report_gen = ReportGenerator(self.output_dir)
    
    def generate_report(self) -> Path:
        """Generate complete report with visualizations."""
        logger.info("Starting report generation...")
        
        # Load data from all phases
        logger.info("Loading Phase 1 results...")
        phase1_results = self.loader.load_phase1_results()
        
        logger.info("Loading Phase 2 results...")
        phase2_metadata, phase2_results = self.loader.load_phase2_results()
        
        logger.info("Loading Phase 3 results...")
        phase3_metadata, phase3_results = self.loader.load_phase3_results()
        
        # Load feedback loop results (if available)
        logger.info("Loading Feedback Loop results...")
        feedback_metadata, feedback_entries = self.loader.load_feedback_loop_results()
        feedback_stats = None
        if feedback_entries:
            feedback_stats = StatsCalculator.get_feedback_loop_stats(feedback_entries)
            logger.info(f"Loaded {len(feedback_entries)} feedback loop entries")
        
        # Calculate statistics
        logger.info("Calculating statistics...")
        calc = StatsCalculator(phase1_results, phase2_results, phase3_results)
        model_stats = calc.get_model_stats()
        cve_stats = calc.get_cve_stats()
        sast_summary = calc.get_sast_summary()
        
        # Generate visualizations
        logger.info("Generating visualizations...")
        chart_paths = {}
        
        try:
            chart_paths['model_comparison'] = self.viz_gen.generate_model_comparison_chart(
                model_stats, phase2_results
            )
        except Exception as e:
            logger.warning(f"Failed to generate model comparison chart: {e}")
        
        try:
            chart_paths['sast_findings'] = self.viz_gen.generate_sast_findings_chart(sast_summary)
        except Exception as e:
            logger.warning(f"Failed to generate SAST findings chart: {e}")
        
        try:
            chart_paths['cve_success'] = self.viz_gen.generate_cve_success_chart(cve_stats)
        except Exception as e:
            logger.warning(f"Failed to generate CVE success chart: {e}")
        
        try:
            chart_paths['execution_times'] = self.viz_gen.generate_execution_time_chart(model_stats)
        except Exception as e:
            logger.warning(f"Failed to generate execution time chart: {e}")
        
        try:
            chart_paths['pipeline_overview'] = self.viz_gen.generate_pipeline_summary_chart(
                phase1_results, phase2_metadata, phase3_metadata
            )
        except Exception as e:
            logger.warning(f"Failed to generate pipeline overview chart: {e}")
        
        # Generate report
        logger.info("Generating Markdown report...")
        report_path = self.report_gen.generate_full_report(
            phase1_results=phase1_results,
            phase2_metadata=phase2_metadata,
            phase2_results=phase2_results,
            phase3_metadata=phase3_metadata,
            phase3_results=phase3_results,
            model_stats=model_stats,
            cve_stats=cve_stats,
            sast_summary=sast_summary,
            chart_paths=chart_paths,
            feedback_entries=feedback_entries if feedback_entries else None,
            feedback_stats=feedback_stats
        )
        
        logger.info(f"Report generation complete: {report_path}")
        logger.info(f"Charts saved to: {self.output_dir}")
        
        return report_path

# =============================================================================
# CLI Entry Point
# =============================================================================

def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="AI-SSD Phase 4: Automated Reporting Pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate full report
  python reporter.py
  
  # Generate report with custom output directory
  python reporter.py --output-dir /path/to/reports
  
  # Verbose output
  python reporter.py --verbose
        """
    )
    
    parser.add_argument(
        '--base-dir',
        type=str,
        default=str(BASE_DIR),
        help='Base directory for the project (default: script directory)'
    )
    
    parser.add_argument(
        '--output-dir',
        type=str,
        default=None,
        help='Output directory for reports (default: <base-dir>/reports)'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose output'
    )
    
    return parser.parse_args()


def main():
    """Main entry point."""
    args = parse_arguments()
    
    # Setup logging
    global logger
    logger = setup_logging(args.verbose)
    
    base_dir = Path(args.base_dir)
    output_dir = Path(args.output_dir) if args.output_dir else None
    
    try:
        reporter = PipelineReporter(base_dir, output_dir)
        report_path = reporter.generate_report()
        
        print(f"\n{'='*60}")
        print("AI-SSD Phase 4: Report Generation Complete")
        print(f"{'='*60}")
        print(f"Report: {report_path}")
        print(f"Charts: {reporter.output_dir}")
        print(f"{'='*60}\n")
        
    except KeyboardInterrupt:
        print("\nReport generation interrupted by user")
        sys.exit(130)
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
