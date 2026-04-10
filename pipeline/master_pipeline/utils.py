import logging
import time
from datetime import datetime
from typing import List, Optional, Tuple
from urllib.parse import urlparse, urlunparse
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


# =========================================================================
# GPU availability helpers (for LLM-dependent phases)
# =========================================================================

def check_gpu_availability(api_endpoint: str) -> Tuple[bool, str]:
    """Check if any GPU VRAM is available on the Ollama server.

    Queries ``/api/ps`` to see which models are currently loaded and how
    much VRAM they occupy.

    Returns:
        (gpu_free, detail_message)
        *gpu_free* is True when NO model is loaded or the loaded model(s)
        leave significant VRAM free.  False when VRAM is fully occupied.
    """
    import requests

    parsed = urlparse(api_endpoint)
    ps_url = urlunparse((parsed.scheme, parsed.netloc, "/api/ps", "", "", ""))

    try:
        resp = requests.get(ps_url, timeout=10)
        resp.raise_for_status()
        running = resp.json().get("models", [])
    except Exception as exc:
        return True, f"Could not query /api/ps ({exc}) — assuming GPU is available."

    if not running:
        return True, "No models currently loaded on the Ollama server — GPU is free."

    total_vram = sum(entry.get("size_vram", 0) for entry in running)
    model_names = [entry.get("name", "?") for entry in running]

    if total_vram == 0:
        return True, (
            f"Models loaded ({', '.join(model_names)}) are running on CPU — "
            "GPU appears free."
        )

    vram_gib = total_vram / (1024 ** 3)
    return False, (
        f"GPU VRAM occupied: {vram_gib:.1f} GiB by {', '.join(model_names)}. "
        "Starting another model may cause CPU-only inference (very slow)."
    )


def prompt_gpu_action(phase_name: str, detail: str) -> str:
    """Interactive prompt when GPU is unavailable before an LLM phase.

    Returns one of: ``"wait"``, ``"skip"``, ``"continue"``
    """
    print(f"\n{'─'*70}")
    print(f"  ⚠  GPU BUSY — {phase_name}")
    print(f"{'─'*70}")
    print(f"  {detail}\n")
    print("  Options:")
    print("    [W] Wait — poll every 30 s until GPU is free, then proceed")
    print("    [S] Skip — skip this LLM phase entirely")
    print("    [C] Continue — proceed anyway (will run on CPU, much slower)")
    print()

    while True:
        try:
            choice = input("  Choose [W/S/C]: ").strip().upper()
        except (EOFError, KeyboardInterrupt):
            print()
            return "skip"
        if choice in ("W", "S", "C"):
            return {"W": "wait", "S": "skip", "C": "continue"}[choice]
        print("  Invalid choice. Please enter W, S, or C.")


def wait_for_gpu(api_endpoint: str, poll_interval: int = 30,
                 timeout: int = 0) -> bool:
    """Block until GPU VRAM is free on the Ollama server.

    Args:
        api_endpoint: Ollama API endpoint (e.g. ``http://host:port/api/chat``)
        poll_interval: Seconds between polls.
        timeout: Max seconds to wait.  0 = wait indefinitely.

    Returns:
        True if GPU became free, False if timed out.
    """
    start = time.time()
    while True:
        free, detail = check_gpu_availability(api_endpoint)
        if free:
            logger.info("GPU is now available — proceeding.")
            return True
        elapsed = time.time() - start
        if timeout and elapsed >= timeout:
            logger.warning("GPU wait timed out after %d s.", int(elapsed))
            return False
        remaining = ""
        if timeout:
            remaining = f" ({int(timeout - elapsed)}s remaining)"
        logger.info("Waiting for GPU to free up%s … (%s)", remaining, detail)
        time.sleep(poll_interval)

