"""
Syntax Validation module.

Validates PoC files using language-specific tools (GCC for C, ``py_compile``
for Python, ``bash -n`` for Shell, etc.) and flags invalid files for
manual supervision.
"""

from __future__ import annotations

import ast
import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..models import CVEEntry, Dataset, SyntaxValidationResult
from ..utils.file_utils import (
    detect_language_from_content,
    detect_language_from_path,
    get_file_extension_for_language,
)
from .base import PipelineModule

logger = logging.getLogger(__name__)


class SyntaxValidator(PipelineModule):
    """Pipeline module: *Syntax Validation*.

    Reads ``context["dataset"]`` and validates PoC source code from each
    exploit entry.  Writes results to ``context["syntax_results"]`` and
    copies invalid files to a manual-supervision directory.
    """

    # ----- main entry point -----

    def run(self, context: Dict[str, Any]) -> Dict[str, Any]:
        cfg = self.config.get("syntax_validator", {})
        manual_dir = Path(cfg.get("manual_supervision_dir", "manual_supervision"))
        report_path = Path(cfg.get("report_path", "syntax_validation_report.json"))

        manual_dir.mkdir(parents=True, exist_ok=True)

        dataset: Dataset = context.get("dataset", Dataset())
        results: Dict[str, Dict] = {}
        valid_count = invalid_count = flagged_count = 0

        for cve_id, entry in dataset.cves.items():
            for idx, exploit in enumerate(entry.exploits):
                content = exploit.source_code_content
                if not content:
                    continue

                lang = exploit.language
                if lang == "unknown":
                    lang = detect_language_from_content(content)

                key = f"{cve_id}:{idx}"
                vr = self._validate(content, lang, cfg)

                results[key] = vr.to_dict()
                results[key]["cve_id"] = cve_id
                results[key]["exploit_idx"] = idx

                if vr.is_valid:
                    valid_count += 1
                else:
                    invalid_count += 1

                if vr.needs_manual_review:
                    flagged_count += 1
                    self._flag_for_manual(cve_id, idx, content, lang, vr, manual_dir)

        self.logger.info(
            "Syntax Validation: %d valid, %d invalid, %d flagged for review",
            valid_count, invalid_count, flagged_count,
        )

        # Persist report
        self._save_report(results, report_path)

        context["syntax_results"] = results
        return context

    # ------------------------------------------------------------------
    # Dispatch to per-language validators
    # ------------------------------------------------------------------

    def _validate(self, content: str, language: str, cfg: Dict) -> SyntaxValidationResult:
        validators = {
            "c": self._validate_c,
            "python": self._validate_python,
            "shell": self._validate_shell,
            "ruby": self._validate_ruby,
            "perl": self._validate_perl,
            "php": self._validate_php,
        }
        fn = validators.get(language)
        if fn:
            return fn(content, cfg)
        # Unrecognised / text language – flag for manual review
        return SyntaxValidationResult(
            is_valid=False, language=language,
            errors=["unrecognised_language"],
            needs_manual_review=True,
        )

    # ------------------------------------------------------------------
    # C validation
    # ------------------------------------------------------------------

    def _validate_c(self, content: str, cfg: Dict) -> SyntaxValidationResult:
        errors: List[str] = []
        warnings: List[str] = []

        try:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".c", delete=False) as f:
                f.write(content)
                tmp = f.name

            result = subprocess.run(
                ["gcc", "-fsyntax-only", "-c", "-w", "-Wno-implicit-function-declaration", tmp],
                capture_output=True, text=True, timeout=30,
            )
            os.unlink(tmp)

            if result.returncode == 0:
                return SyntaxValidationResult(True, "c")

            err_msg = (result.stderr or result.stdout).strip()
            err_msg = re.sub(r"/tmp/tmp\w+\.c:", "line ", err_msg)

            # Environment errors (Xcode license, missing SDK…)
            env_patterns = [r"Xcode license", r"xcrun: error", r"developer tools"]
            if any(re.search(p, err_msg, re.I) for p in env_patterns):
                warnings.append(f"gcc_env_issue:{err_msg[:200]}")
                ok, serr = self._validate_c_structure(content)
                if not ok:
                    errors.extend(serr)
                    return SyntaxValidationResult(False, "c", errors, warnings, True)
                return SyntaxValidationResult(True, "c", warnings=warnings)

            # Missing-header errors (expected for library code)
            header_patterns = [r"fatal error:.*\.h.*No such file", r"#include.*not found"]
            if any(re.search(p, err_msg, re.I) for p in header_patterns):
                warnings.append(f"missing_headers:{err_msg[:200]}")
                return SyntaxValidationResult(True, "c", warnings=warnings)

            errors.append(err_msg)
            return SyntaxValidationResult(False, "c", errors, needs_manual_review=True)

        except subprocess.TimeoutExpired:
            if "tmp" in dir() and os.path.exists(tmp):
                os.unlink(tmp)
            return SyntaxValidationResult(False, "c", ["gcc_timeout"], needs_manual_review=True)
        except FileNotFoundError:
            # GCC not installed – structural fallback
            warnings.append("gcc_not_found")
            ok, serr = self._validate_c_structure(content)
            if not ok:
                return SyntaxValidationResult(False, "c", serr, warnings, True)
            return SyntaxValidationResult(True, "c", warnings=warnings)
        except Exception as exc:
            return SyntaxValidationResult(False, "c", [str(exc)], needs_manual_review=True)

    @staticmethod
    def _validate_c_structure(content: str) -> Tuple[bool, List[str]]:
        """Basic structural validation without a compiler."""
        errors: List[str] = []
        cleaned = re.sub(r"//.*$", "", content, flags=re.MULTILINE)
        cleaned = re.sub(r"/\*.*?\*/", "", cleaned, flags=re.DOTALL)
        cleaned = re.sub(r'"(?:[^"\\]|\\.)*"', '""', cleaned)

        # Check balanced braces
        if cleaned.count("{") != cleaned.count("}"):
            errors.append("unbalanced_braces")
        if cleaned.count("(") != cleaned.count(")"):
            errors.append("unbalanced_parentheses")
        return (len(errors) == 0, errors)

    # ------------------------------------------------------------------
    # Python validation
    # ------------------------------------------------------------------

    def _validate_python(self, content: str, cfg: Dict) -> SyntaxValidationResult:
        try:
            ast.parse(content)
            return SyntaxValidationResult(True, "python")
        except SyntaxError as exc:
            return SyntaxValidationResult(
                False, "python", [f"line {exc.lineno}: {exc.msg}"], needs_manual_review=True
            )
        except Exception as exc:
            return SyntaxValidationResult(False, "python", [str(exc)], needs_manual_review=True)

    # ------------------------------------------------------------------
    # Shell validation
    # ------------------------------------------------------------------

    def _validate_shell(self, content: str, cfg: Dict) -> SyntaxValidationResult:
        try:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".sh", delete=False) as f:
                f.write(content)
                tmp = f.name
            result = subprocess.run(
                ["bash", "-n", tmp], capture_output=True, text=True, timeout=15,
            )
            os.unlink(tmp)
            if result.returncode == 0:
                return SyntaxValidationResult(True, "shell")
            err = (result.stderr or "").strip()
            return SyntaxValidationResult(False, "shell", [err], needs_manual_review=True)
        except FileNotFoundError:
            return SyntaxValidationResult(True, "shell", warnings=["bash_not_found"])
        except Exception as exc:
            return SyntaxValidationResult(False, "shell", [str(exc)], needs_manual_review=True)

    # ------------------------------------------------------------------
    # Ruby validation
    # ------------------------------------------------------------------

    def _validate_ruby(self, content: str, cfg: Dict) -> SyntaxValidationResult:
        try:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".rb", delete=False) as f:
                f.write(content)
                tmp = f.name
            result = subprocess.run(
                ["ruby", "-c", tmp], capture_output=True, text=True, timeout=15,
            )
            os.unlink(tmp)
            if result.returncode == 0:
                return SyntaxValidationResult(True, "ruby")
            err = (result.stderr or "").strip()
            return SyntaxValidationResult(False, "ruby", [err], needs_manual_review=True)
        except FileNotFoundError:
            return SyntaxValidationResult(True, "ruby", warnings=["ruby_not_found"])
        except Exception as exc:
            return SyntaxValidationResult(False, "ruby", [str(exc)], needs_manual_review=True)

    # ------------------------------------------------------------------
    # Perl validation
    # ------------------------------------------------------------------

    def _validate_perl(self, content: str, cfg: Dict) -> SyntaxValidationResult:
        try:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".pl", delete=False) as f:
                f.write(content)
                tmp = f.name
            result = subprocess.run(
                ["perl", "-c", tmp], capture_output=True, text=True, timeout=15,
            )
            os.unlink(tmp)
            if result.returncode == 0:
                return SyntaxValidationResult(True, "perl")
            err = (result.stderr or "").strip()
            return SyntaxValidationResult(False, "perl", [err], needs_manual_review=True)
        except FileNotFoundError:
            return SyntaxValidationResult(True, "perl", warnings=["perl_not_found"])
        except Exception as exc:
            return SyntaxValidationResult(False, "perl", [str(exc)], needs_manual_review=True)

    # ------------------------------------------------------------------
    # PHP validation
    # ------------------------------------------------------------------

    def _validate_php(self, content: str, cfg: Dict) -> SyntaxValidationResult:
        try:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".php", delete=False) as f:
                f.write(content)
                tmp = f.name
            result = subprocess.run(
                ["php", "-l", tmp], capture_output=True, text=True, timeout=15,
            )
            os.unlink(tmp)
            if result.returncode == 0:
                return SyntaxValidationResult(True, "php")
            err = (result.stderr or result.stdout or "").strip()
            return SyntaxValidationResult(False, "php", [err], needs_manual_review=True)
        except FileNotFoundError:
            return SyntaxValidationResult(True, "php", warnings=["php_not_found"])
        except Exception as exc:
            return SyntaxValidationResult(False, "php", [str(exc)], needs_manual_review=True)

    # ------------------------------------------------------------------
    # Manual supervision / reporting
    # ------------------------------------------------------------------

    def _flag_for_manual(
        self,
        cve_id: str,
        exploit_idx: int,
        content: str,
        language: str,
        vr: SyntaxValidationResult,
        manual_dir: Path,
    ) -> None:
        ext = get_file_extension_for_language(language)
        dest = manual_dir / f"{cve_id}_{exploit_idx}{ext}"
        try:
            dest.write_text(content, encoding="utf-8")
            # Also save a companion JSON with the validation details
            meta_dest = manual_dir / f"{cve_id}_{exploit_idx}.validation.json"
            meta_dest.write_text(json.dumps(vr.to_dict(), indent=2), encoding="utf-8")
            self.logger.debug("Flagged for manual review: %s", dest)
        except Exception as exc:
            self.logger.warning("Failed to flag %s for manual review: %s", cve_id, exc)

    @staticmethod
    def _save_report(results: Dict, path: Path) -> None:
        summary = {
            "generated_at": datetime.now().isoformat(),
            "total_validated": len(results),
            "valid": sum(1 for r in results.values() if r.get("is_valid")),
            "invalid": sum(1 for r in results.values() if not r.get("is_valid")),
            "needs_review": sum(1 for r in results.values() if r.get("needs_manual_review")),
            "details": results,
        }
        try:
            path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
            logger.info("Syntax validation report saved to %s", path)
        except IOError as exc:
            logger.error("Failed to save report: %s", exc)
