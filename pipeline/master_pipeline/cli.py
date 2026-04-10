import sys
import argparse
import logging
from pathlib import Path
from .config import (BASE_DIR, DEFAULT_MODELS, MAX_RETRIES,
                     MANUAL_VERIFY_TIMEOUT, MANUAL_VERIFY_POLL_INTERVAL,
                     PHASE_SCRIPTS, PipelineConfig, get_config)
from .utils import setup_logging, print_banner
from .orchestrator import MasterPipeline

logger = logging.getLogger('pipeline')

def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="AI-SSD Master Pipeline Orchestrator with Iterative Feedback Loop",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run complete pipeline with feedback loop
  python pipeline.py
  
  # Run for specific CVE
  python pipeline.py --cve CVE-2015-7547
  
  # Run with specific models
  python pipeline.py --models qwen2.5-coder:7b qwen2.5:7b
  
  # Run only phases 2-4 (skip reproduction)
  python pipeline.py --phases 2 3 4
  
  # Disable feedback loop (no retries)
  python pipeline.py --no-feedback-loop
  
  # Custom max retries for feedback loop
  python pipeline.py --max-retries 5
  
  # Run with cleanup and verbose output
  python pipeline.py --cleanup --verbose
  
  # Dry run to see what would be executed
  python pipeline.py --dry-run
        """
    )
    
    parser.add_argument(
        '--base-dir',
        type=str,
        default=str(BASE_DIR),
        help='Base directory for the project (default: script directory)'
    )
    
    parser.add_argument(
        '--cve',
        type=str,
        nargs='+',
        dest='cves',
        metavar='CVE',
        help='Specific CVE ID(s) to process (e.g., CVE-2015-7547)'
    )
    
    parser.add_argument(
        '--models',
        type=str,
        nargs='+',
        metavar='MODEL',
        help=f'Specific model(s) to use for patch generation. Available: {", ".join(DEFAULT_MODELS)}'
    )
    
    parser.add_argument(
        '--phases',
        type=int,
        nargs='+',
        default=[0, 1, 2, 3, 4],
        choices=[0, 1, 2, 3, 4],
        help='Phases to execute (0=Aggregation, 1=Reproduction, 2=Generation, 3=Validation, 4=Reporting)'
    )
    
    _cfg = get_config()
    parser.add_argument(
        '--phase0-config',
        type=str,
        default=str(_cfg.get('phase0_config', 'cve_aggregator/glibc_config.yaml')),
        help='Path to Phase 0 config file (relative to base-dir or absolute)'
    )
    
    parser.add_argument(
        '--build-timeout',
        type=int,
        default=int(_cfg.get('build_timeout', 3600)),
        help='Docker build timeout in seconds (default: from config.yaml)'
    )
    
    parser.add_argument(
        '--run-timeout',
        type=int,
        default=int(_cfg.get('run_timeout', 300)),
        help='Container run timeout in seconds (default: from config.yaml)'
    )
    
    parser.add_argument(
        '--skip-sast',
        action='store_true',
        help='Skip SAST analysis in validation phase'
    )
    
    parser.add_argument(
        '--cleanup',
        action='store_true',
        help='Clean up Docker images and containers after execution'
    )
    
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Show what would be executed without running'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose output'
    )
    
    # Feedback Loop Arguments
    parser.add_argument(
        '--no-feedback-loop',
        action='store_true',
        help='Disable the iterative feedback loop (no retries for failed patches)'
    )
    
    parser.add_argument(
        '--max-retries',
        type=int,
        default=MAX_RETRIES,
        help=f'Maximum retry attempts for failed patches in feedback loop (default: {MAX_RETRIES})'
    )
    
    # Phase 0 Manual Verification Arguments
    parser.add_argument(
        '--manual-verify-timeout',
        type=int,
        default=MANUAL_VERIFY_TIMEOUT,
        help=f'Timeout in seconds for manual verification wait (default: {MANUAL_VERIFY_TIMEOUT})'
    )
    
    parser.add_argument(
        '--manual-verify-poll',
        type=int,
        default=MANUAL_VERIFY_POLL_INTERVAL,
        help=f'Poll interval in seconds for manual verification (default: {MANUAL_VERIFY_POLL_INTERVAL})'
    )
    
    return parser.parse_args()


def main():
    """Main entry point."""
    args = parse_arguments()
    
    # Setup logging
    setup_logging(args.verbose)
    
    # Build configuration with feedback loop settings
    config = PipelineConfig(
        base_dir=Path(args.base_dir),
        cves=args.cves,
        models=args.models,
        phases=sorted(args.phases),
        verbose=args.verbose,
        cleanup=args.cleanup,
        skip_sast=args.skip_sast,
        dry_run=args.dry_run,
        build_timeout=args.build_timeout,
        run_timeout=args.run_timeout,
        enable_feedback_loop=not args.no_feedback_loop,
        max_retries=args.max_retries,
        phase0_config=args.phase0_config,
        manual_verify_timeout=args.manual_verify_timeout,
        manual_verify_poll_interval=args.manual_verify_poll,
    )
    
    logger.info("Pipeline Configuration:")
    logger.info(f"  Base Directory: {config.base_dir}")
    logger.info(f"  Phase 0 Config: {config.phase0_config}")
    logger.info(f"  CVEs: {'All' if not config.cves else config.cves}")
    logger.info(f"  Models: {config.models or 'All'}")
    logger.info(f"  Phases to Execute: {config.phases}")
    logger.info(f"  Build Timeout: {config.build_timeout}s")
    logger.info(f"  Run Timeout: {config.run_timeout}s")
    logger.info(f"  Skip SAST: {config.skip_sast}")
    logger.info(f"  Cleanup: {config.cleanup}")
    logger.info(f"  Verbose: {config.verbose}")
    logger.info(f"  Feedback Loop: {'Enabled' if config.enable_feedback_loop else 'Disabled'}")
    if config.enable_feedback_loop:
        logger.info(f"  Max Retries: {config.max_retries}")
    logger.info(f"  Manual Verify Timeout: {config.manual_verify_timeout}s")
    logger.info(f"  Manual Verify Poll: {config.manual_verify_poll_interval}s")
    
    # Handle dry run
    if args.dry_run:
        print("\n" + "="*70)
        print("  DRY RUN - No actions will be taken")
        print("="*70 + "\n")
        print("Configuration:")
        print(f"  Base Directory: {config.base_dir}")
        print(f"  Phase 0 Config: {config.phase0_config}")
        print(f"  CVEs: {config.cves or 'All'}")
        print(f"  Models: {config.models or 'All'}")
        print(f"  Phases to Execute: {config.phases}")
        print(f"  Build Timeout: {config.build_timeout}s")
        print(f"  Run Timeout: {config.run_timeout}s")
        print(f"  Skip SAST: {config.skip_sast}")
        print(f"  Cleanup: {config.cleanup}")
        print(f"  Verbose: {config.verbose}")
        print(f"  Feedback Loop: {'Enabled' if config.enable_feedback_loop else 'Disabled'}")
        if config.enable_feedback_loop:
            print(f"  Max Retries: {config.max_retries}")
        print(f"  Manual Verify Timeout: {config.manual_verify_timeout}s")
        print(f"  Manual Verify Poll: {config.manual_verify_poll_interval}s")
        
        print("\nPhases that would be executed:")
        for phase in config.phases:
            script = PHASE_SCRIPTS.get(phase, "Unknown")
            script_path = config.base_dir / script
            exists = "✅" if script_path.exists() else "❌"
            print(f"  Phase {phase}: {script} {exists}")
        
        if 0 in config.phases:
            print("\nPhase 0 Flow:")
            print("  cve_aggregator → glibc_cve_poc_complete.csv")
            print(f"  → Wait up to {config.manual_verify_timeout}s for manual verification")
            print("  → Proceed to Phase 1 (exclude pending CVEs)")
        
        if config.enable_feedback_loop:
            print("\nFeedback Loop Flow:")
            print("  Phase 3 (Validation) → Failed? → Extract Failure Context")
            print("  → Phase 2 (Regenerate with Context) → Phase 3 (Re-validate)")
            print(f"  → Repeat up to {config.max_retries}x → Success or 'Unpatchable'")
        
        return 0
    
    # Run pipeline
    try:
        pipeline = MasterPipeline(config)
        success = pipeline.run()
        return 0 if success else 1
        
    except KeyboardInterrupt:
        print("\n\nPipeline interrupted by user")
        logger.warning("Pipeline interrupted by user")
        return 130
    
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
