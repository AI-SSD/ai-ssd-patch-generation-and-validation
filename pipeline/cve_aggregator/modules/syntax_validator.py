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
        allow_manual_without_commit = cfg.get("allow_manual_without_commit", True)

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
                if lang in ("unknown", "text"):
                    detected = detect_language_from_content(content)
                    if detected != "unknown":
                        lang = detected

                key = f"{cve_id}:{idx}"
                vr = self._validate(content, lang, cfg)

                # Persist successful auto-commenting so downstream output writes cleaned PoCs.
                if vr.is_valid and any(w.startswith("auto_commented_prose_lines:") for w in vr.warnings):
                    fixed_content, changed = self._auto_comment_uncommented_prose_for_language(content, lang)
                    if changed > 0 and fixed_content != content:
                        exploit.source_code_content = fixed_content
                        content = fixed_content

                results[key] = vr.to_dict()
                results[key]["cve_id"] = cve_id
                results[key]["exploit_idx"] = idx

                if vr.is_valid:
                    valid_count += 1
                else:
                    invalid_count += 1

                if vr.needs_manual_review:
                    if not entry.has_commits and not allow_manual_without_commit:
                        self.logger.debug("Skipping manual flagged items for %s because it has no commits.", cve_id)
                    else:
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

    @staticmethod
    def _comment_prefix_for_language(language: str) -> str:
        prefixes = {
            "c": "// ",
            "python": "# ",
            "shell": "# ",
            "ruby": "# ",
            "perl": "# ",
            "php": "// ",
        }
        return prefixes.get(language, "# ")

    def _is_code_anchor_for_language(self, line: str, language: str) -> bool:
        """Return True when a line strongly indicates source code for *language*."""
        if language == "c":
            return self._is_c_code_anchor(line)

        s = line.strip()
        if not s:
            return False

        patterns = {
            "python": [
                r"^(from|import)\b",
                r"^(def|class)\b",
                r"^if\s+__name__\s*==",
                r"^[A-Za-z_]\w*\s*=",
                r"^@\w+",
            ],
            "shell": [
                r"^#!",
                r"^[A-Za-z_]\w*=",
                r"^(if|for|while|case|function)\b",
                r"^(echo|printf|exec|export|test|\.|source)\b",
            ],
            "ruby": [
                r"^(require|class|module|def|begin|end|if|unless)\b",
                r"^(puts|print|p)\b",
                r"^[A-Za-z_]\w*\s*=",
            ],
            "perl": [
                r"^#!",
                r"^(use|my|sub|package)\b",
                r"^print\b",
                r"^[\$@%][A-Za-z_]",
            ],
            "php": [
                r"^<\?php",
                r"^(function|class|if|require|include|echo)\b",
                r"^\$[A-Za-z_]",
            ],
        }
        return any(re.search(p, s) for p in patterns.get(language, []))

    @staticmethod
    def _is_uncommented_prose_line_generic(line: str) -> bool:
        """Heuristic for plain-English prose accidentally embedded in source files."""
        s = line.strip()
        if not s:
            return False
        if s.startswith(("//", "/*", "*/", "*", "#", "--", "<!--", "<?")):
            return False
        if any(ch in s for ch in (";", "{", "}", "=", "$", "`", "|", "&", "\t", "\"", "'")):
            return False

        words = re.findall(r"[A-Za-z]+", s)
        if len(words) < 6:
            return False

        lowered = s.lower()
        prose_hints = [
            "vulnerab", "exploit", "attacker", "application", "library", "overflow",
            "denial", "successful", "failed", "execute arbitrary", "context of",
        ]
        return any(h in lowered for h in prose_hints)

    def _auto_comment_uncommented_prose_for_language(self, content: str, language: str) -> Tuple[str, int]:
        """Comment prose-like lines anywhere in the file for a given language."""
        lines = content.splitlines()
        has_anchor = any(self._is_code_anchor_for_language(line, language) for line in lines)
        if not has_anchor:
            return content, 0

        prefix = self._comment_prefix_for_language(language)
        changed = 0
        out_lines = list(lines)
        for idx, line in enumerate(out_lines):
            line = out_lines[idx]
            if self._is_code_anchor_for_language(line, language):
                continue
            if self._is_uncommented_prose_line_generic(line):
                indent = re.match(r"^\s*", line).group(0)
                out_lines[idx] = f"{indent}{prefix}{line[len(indent):]}"
                changed += 1

        if changed == 0:
            return content, 0

        out = "\n".join(out_lines)
        if content.endswith("\n"):
            out += "\n"
        return out, changed

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
            result = fn(content, cfg)
            if result.is_valid or not result.needs_manual_review:
                return result

            fixed_content, commented_lines = self._auto_comment_uncommented_prose_for_language(
                content, language
            )
            if commented_lines == 0:
                return result

            retry = fn(fixed_content, cfg)
            if retry.is_valid:
                retry.warnings.append(f"auto_commented_prose_lines:{commented_lines}")
                return retry

            result.warnings.append(f"auto_commented_prose_attempted:{commented_lines}")
            return result
        # Unrecognised / text language – flag for manual review
        return SyntaxValidationResult(
            is_valid=False, language=language,
            errors=["unrecognised_language"],
            needs_manual_review=True,
        )

    # ------------------------------------------------------------------
    # C validation
    # ------------------------------------------------------------------

    @staticmethod
    def _run_c_syntax_check(content: str) -> Tuple[int, str]:
        """Run C syntax-only compilation and return ``(returncode, message)``."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".c", delete=False) as f:
            f.write(content)
            tmp = f.name

        try:
            result = subprocess.run(
                [
                    "gcc", "-fsyntax-only", "-c", "-w",
                    "-Wno-implicit-function-declaration", "-Wno-implicit-int", tmp,
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )
            err_msg = (result.stderr or result.stdout).strip()
            err_msg = re.sub(r"/tmp/tmp\w+\.c:", "line ", err_msg)
            return result.returncode, err_msg
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)

    @staticmethod
    def _is_c_code_anchor(line: str) -> bool:
        """Return True when a line strongly indicates real C source code."""
        s = line.strip()
        if not s:
            return False
        if re.match(r"^#\s*(include|define|if|ifdef|ifndef|elif|else|endif|pragma)\b", s):
            return True
        if re.match(
            r"^(typedef|struct|union|enum|static|extern|const|volatile|unsigned|signed|void|char|short|int|long|float|double)\b",
            s,
        ):
            return True
        if re.match(r"^[A-Za-z_]\w*\s*\(", s):
            return True
        return False

    @staticmethod
    def _is_uncommented_prose_line(line: str) -> bool:
        """Heuristic for plain-English prose accidentally embedded in C files."""
        s = line.strip()
        if not s:
            return False
        if s.startswith(("//", "/*", "*/", "*", "#")):
            return False
        if any(ch in s for ch in (";", "{", "}", "(")):
            return False
        words = re.findall(r"[A-Za-z]+", s)
        if len(words) < 5:
            return False
        lowered = s.lower()
        prose_hints = ["vulnerab", "exploit", "attacker", "application", "library", "overflow", "denial"]
        return any(h in lowered for h in prose_hints)

    def _auto_comment_uncommented_prose(self, content: str) -> Tuple[str, int]:
        """Backward-compatible C-specific wrapper over generic auto-commenting."""
        return self._auto_comment_uncommented_prose_for_language(content, "c")

    def _validate_c(self, content: str, cfg: Dict) -> SyntaxValidationResult:
        errors: List[str] = []
        warnings: List[str] = []

        try:
            code, err_msg = self._run_c_syntax_check(content)

            if code == 0:
                return SyntaxValidationResult(True, "c")

            # Auto-fix common scraped PoCs where prose is left uncommented.
            fixed_content, commented_lines = self._auto_comment_uncommented_prose(content)
            if commented_lines > 0:
                fixed_code, fixed_err = self._run_c_syntax_check(fixed_content)
                if fixed_code == 0:
                    warnings.append(f"auto_commented_prose_lines:{commented_lines}")
                    return SyntaxValidationResult(True, "c", warnings=warnings)
                # Keep the most informative error from the retried content.
                err_msg = fixed_err or err_msg
                warnings.append(f"auto_commented_prose_lines:{commented_lines}")

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
            header_patterns = [
                r"fatal error:.*\.h.*No such file",
                r"fatal error:.*\.h.*not found",
                r"#include.*not found",
            ]
            if any(re.search(p, err_msg, re.I) for p in header_patterns):
                warnings.append(f"missing_headers:{err_msg[:200]}")
                return SyntaxValidationResult(True, "c", warnings=warnings)

            errors.append(err_msg)
            return SyntaxValidationResult(False, "c", errors, needs_manual_review=True)

        except subprocess.TimeoutExpired:
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
            # Detect Python 2 code and tolerate known Py2-only syntax
            if self._is_python2_syntax_error(content, exc):
                return SyntaxValidationResult(
                    True, "python",
                    warnings=[f"python2_syntax:line {exc.lineno}: {exc.msg}"],
                )
            return SyntaxValidationResult(
                False, "python", [f"line {exc.lineno}: {exc.msg}"], needs_manual_review=True
            )
        except Exception as exc:
            return SyntaxValidationResult(False, "python", [str(exc)], needs_manual_review=True)

    @staticmethod
    def _is_python2_syntax_error(content: str, exc: SyntaxError) -> bool:
        """Return True if the syntax error is due to Python 2 constructs."""
        py2_indicators = [
            r"\bprint\s+[\"\']|\bprint\s+[^(]",  # print "x" or print x
            r"\bexcept\s+\w+\s*,\s*\w+",           # except Error, e:
            r"\braise\s+\w+\s*,",                   # raise Error, msg
        ]
        has_py2 = any(re.search(p, content) for p in py2_indicators)
        py2_msgs = ["Missing parentheses in call to 'print'",
                    "leading zeros in decimal integer literals"]
        msg_match = any(m in (exc.msg or "") for m in py2_msgs)
        return has_py2 or msg_match

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
