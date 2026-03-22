from enum import Enum
from dataclasses import dataclass, asdict, field
from typing import Dict, List, Optional, Any

class PhaseStatus(Enum):
    """Status of a pipeline phase."""
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"


class PatchStatus(Enum):
    """Status of a patch in the iterative feedback loop."""
    PENDING = "pending"
    VALIDATING = "validating"
    SUCCESS = "success"
    RETRYING = "retrying"
    UNPATCHABLE = "unpatchable"
    FAILED = "failed"


@dataclass
class FeedbackLoopResult:
    """Result of the iterative feedback loop for a single patch."""
    cve_id: str
    model_name: str
    final_status: PatchStatus
    total_attempts: int
    successful_attempt: Optional[int] = None  # Which attempt succeeded (1-based)
    final_patch_path: Optional[str] = None
    validation_history: List[Dict[str, Any]] = field(default_factory=list)
    failure_reason: Optional[str] = None
    total_duration_seconds: float = 0.0
    start_time: Optional[str] = None  # ISO format start time
    end_time: Optional[str] = None  # ISO format end time
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "model_name": self.model_name,
            "final_status": self.final_status.value,
            "total_attempts": self.total_attempts,
            "successful_attempt": self.successful_attempt,
            "final_patch_path": self.final_patch_path,
            "validation_history": self.validation_history,
            "failure_reason": self.failure_reason,
            "total_duration_seconds": self.total_duration_seconds,
            "start_time": self.start_time,
            "end_time": self.end_time,
        }


@dataclass
class PhaseResult:
    """Result of a single phase execution."""
    phase: int
    name: str
    status: PhaseStatus
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    duration_seconds: float = 0.0
    exit_code: int = 0
    output_files: List[str] = field(default_factory=list)
    error_message: Optional[str] = None
    stdout: str = ""
    stderr: str = ""



@dataclass
class PipelineSummary:
    """Summary of the entire pipeline run."""
    start_time: str
    end_time: str
    duration_seconds: float
    config: Dict[str, Any]
    phases_completed: int
    phases_failed: int
    results: List[Dict[str, Any]]
    overall_status: str
    # Feedback Loop Summary
    feedback_loop_results: List[Dict[str, Any]] = field(default_factory=list)
    total_patches_processed: int = 0
    patches_successful: int = 0
    patches_unpatchable: int = 0
    total_retry_attempts: int = 0

