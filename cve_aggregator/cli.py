"""
CLI entry point for the CVE Aggregator pipeline.

Usage examples:
    # Full pipeline with default config
    python -m cve_aggregator

    # Custom config file
    python -m cve_aggregator --config my_project.yaml

    # Skip specific modules
    python -m cve_aggregator --skip SyntaxValidator

    # Re-export CSV only (from existing dataset)
    python -m cve_aggregator --export-csv

    # Re-export PoC files only
    python -m cve_aggregator --export-poc
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .pipeline import (
    PipelineOrchestrator,
    load_config,
    setup_logging,
    DEFAULT_PIPELINE,
)
from .modules.output_generator import OutputGenerator
from .models import Dataset


def parse_args(argv=None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="cve_aggregator",
        description="Modular CVE Aggregator & PoC Extraction Pipeline",
    )
    p.add_argument(
        "--config", "-c",
        help="Path to YAML configuration file (default: aggregator_config.yaml)",
    )
    p.add_argument(
        "--skip",
        nargs="*",
        default=[],
        metavar="MODULE",
        help="Module class names to skip (e.g. SyntaxValidator CommitDiscovery)",
    )
    p.add_argument(
        "--export-csv",
        action="store_true",
        help="Re-export CSV and PoC files from existing filtered JSON (skip fetching).",
    )
    p.add_argument(
        "--export-poc",
        action="store_true",
        help="Re-export PoC files only from existing filtered JSON.",
    )
    p.add_argument(
        "--list-modules",
        action="store_true",
        help="Show available pipeline modules and exit.",
    )
    return p.parse_args(argv)


def cmd_list_modules() -> None:
    for cls in DEFAULT_PIPELINE:
        print(f"  {cls.__name__:25s} – {(cls.__doc__ or '').strip().split(chr(10))[0]}")


def cmd_export_csv(config: dict) -> int:
    """Re-export from existing filtered dataset."""
    cfg_out = config.get("output", {})
    filtered_path = Path(cfg_out.get("filtered_json_path", "cve_poc_map_filtered.json"))

    if not filtered_path.exists():
        print(f"Filtered dataset not found: {filtered_path}", file=sys.stderr)
        print("Run the full pipeline first.", file=sys.stderr)
        return 1

    with open(filtered_path, "r", encoding="utf-8") as fh:
        ds = Dataset.from_dict(json.load(fh))

    context = {"dataset": ds, "config": config, "syntax_results": {}}
    gen = OutputGenerator(config)
    gen.run(context)
    return 0


def main(argv=None) -> int:
    args = parse_args(argv)

    if args.list_modules:
        cmd_list_modules()
        return 0

    config = load_config(args.config)
    setup_logging(config)

    if args.export_csv or args.export_poc:
        return cmd_export_csv(config)

    orchestrator = PipelineOrchestrator(
        config,
        skip_modules=args.skip,
    )
    ctx = orchestrator.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
