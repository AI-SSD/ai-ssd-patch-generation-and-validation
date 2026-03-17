"""Allow ``python -m cve_aggregator``."""
from .cli import main
import sys

sys.exit(main())
