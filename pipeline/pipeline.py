#!/usr/bin/env python3
"""
AI-SSD Master Pipeline Orchestrator (Modular Wrapper)

This script is maintained exclusively for backward compatibility. 
Please consider using `python -m master_pipeline` natively in the future.
"""

import sys
from master_pipeline.cli import main

if __name__ == "__main__":
    sys.exit(main())
