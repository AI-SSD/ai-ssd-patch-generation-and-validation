import logging
from datetime import datetime
from typing import List
from .config import LOG_DIR
from .models import PhaseResult, PhaseStatus

def setup_logging(verbose: bool = False) -> logging.Logger:
    """Configure logging for the pipeline."""
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    
    logger = logging.getLogger('pipeline')
    logger.setLevel(logging.DEBUG)
    
    # Clear existing handlers
    logger.handlers.clear()
    
    # Console handler with colors
    console = logging.StreamHandler()
    console.setLevel(logging.DEBUG if verbose else logging.INFO)
    
    class ColorFormatter(logging.Formatter):
        COLORS = {
            'DEBUG': '\033[36m',     # Cyan
            'INFO': '\033[32m',      # Green
            'WARNING': '\033[33m',   # Yellow
            'ERROR': '\033[31m',     # Red
            'CRITICAL': '\033[35m',  # Magenta
        }
        RESET = '\033[0m'
        
        def format(self, record):
            color = self.COLORS.get(record.levelname, self.RESET)
            record.levelname = f"{color}{record.levelname}{self.RESET}"
            return super().format(record)
    
    console.setFormatter(ColorFormatter(
        '%(asctime)s [%(levelname)s] %(message)s',
        datefmt='%H:%M:%S'
    ))
    logger.addHandler(console)
    
    # File handler
    log_file = LOG_DIR / f'pipeline_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s [%(levelname)s] %(message)s'
    ))
    logger.addHandler(file_handler)
    
    return logger

logger = setup_logging()


def print_banner():
    """Print pipeline banner."""
    banner = """
╔═══════════════════════════════════════════════════════════════════╗
║                                                                   ║
║              █████╗ ██╗      ███████╗███████╗██████╗              ║
║             ██╔══██╗██║      ██╔════╝██╔════╝██╔══██╗             ║
║             ███████║██║█████╗███████╗███████╗██║  ██║             ║
║             ██╔══██║██║╚════╝╚════██║╚════██║██║  ██║             ║
║             ██║  ██║██║      ███████║███████║██████╔╝             ║
║             ╚═╝  ╚═╝╚═╝      ╚══════╝╚══════╝╚═════╝              ║
║                                                                   ║
║     Automated Security Patch Generation & Validation Pipeline     ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝
"""
    print(banner)

def print_phase_header(phase: int, name: str):
    """Print phase header."""
    print(f"\n{'='*70}")
    print(f"  PHASE {phase}: {name.upper()}")
    print(f"{'='*70}\n")

def print_summary_table(results: List[PhaseResult]):
    """Print summary table of phase results."""
    print("\n" + "="*70)
    print("  PIPELINE EXECUTION SUMMARY")
    print("="*70)
    print(f"\n{'Phase':<8} {'Name':<25} {'Status':<12} {'Duration':<12} {'Exit':<6}")
    print("-"*70)
    
    for r in results:
        status_icon = {
            PhaseStatus.SUCCESS: "✅",
            PhaseStatus.FAILED: "❌",
            PhaseStatus.SKIPPED: "⏭️",
            PhaseStatus.PENDING: "⏳",
            PhaseStatus.RUNNING: "🔄"
        }.get(r.status, "❓")
        
        print(f"{r.phase:<8} {r.name:<25} {status_icon} {r.status.value:<10} "
              f"{r.duration_seconds:>8.1f}s   {r.exit_code:<6}")
    
    print("-"*70)

def format_duration(seconds: float) -> str:
    """Format duration in human-readable format."""
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        mins = int(seconds // 60)
        secs = int(seconds % 60)
        return f"{mins}m {secs}s"
    else:
        hours = int(seconds // 3600)
        mins = int((seconds % 3600) // 60)
        return f"{hours}h {mins}m"

