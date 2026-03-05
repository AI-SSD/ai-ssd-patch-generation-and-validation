"""
Abstract base classes for pipeline modules.

Every stage of the CVE Aggregator pipeline inherits from
:class:`PipelineModule` and implements ``run()``.  This makes it trivial
to swap, extend, or skip individual stages.
"""

from __future__ import annotations

import abc
import logging
from typing import Any, Dict


class PipelineModule(abc.ABC):
    """Base class for all pipeline stages.

    Subclasses must implement :meth:`run`.  The *config* dict is the
    resolved YAML configuration (or a relevant subset of it).
    """

    def __init__(self, config: Dict[str, Any], *, logger_name: str | None = None):
        self.config = config
        self.logger = logging.getLogger(logger_name or self.__class__.__name__)

    @abc.abstractmethod
    def run(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Execute the module.

        Parameters
        ----------
        context : dict
            Shared pipeline context.  Each module reads what it needs
            and writes its outputs back into *context* before returning.

        Returns
        -------
        dict
            The (possibly-updated) pipeline context.
        """
        ...

    # Optional hooks that modules can override
    def validate_config(self) -> bool:
        """Return ``True`` if the module's configuration is valid."""
        return True

    def cleanup(self) -> None:
        """Release any resources held by the module."""
        pass
