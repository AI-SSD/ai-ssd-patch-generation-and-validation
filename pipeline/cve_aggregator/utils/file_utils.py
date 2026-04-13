"""
File handling utilities for the CVE Aggregator pipeline.

Language detection, content extraction, text-vs-binary heuristics, etc.
"""

from __future__ import annotations

import logging
import mimetypes
import re
from pathlib import Path
from typing import Optional, Set, Tuple

logger = logging.getLogger(__name__)

# Extensions considered as text / source code
DEFAULT_TEXT_EXTENSIONS: Set[str] = {
    ".c", ".h", ".cc", ".cpp", ".cxx", ".hh", ".hpp", ".hxx",
    ".cs",
    ".py", ".rb", ".pl", ".sh", ".bash", ".java", ".js", ".ts",
    ".php", ".asp", ".aspx", ".jsp", ".txt", ".md", ".rst", ".html", ".xml",
    ".json", ".yaml", ".yml", ".conf", ".cfg", ".ini", ".asm", ".s", ".go",
    ".rs", ".swift", ".kt", ".scala", ".lua", ".r", ".ps1", ".bat", ".cmd",
}


# ---------------------------------------------------------------------------
# Language detection
# ---------------------------------------------------------------------------

_EXT_TO_LANG = {
    ".c": "c", ".h": "c",
    ".cc": "cpp", ".cpp": "cpp", ".cxx": "cpp",
    ".hh": "cpp", ".hpp": "cpp", ".hxx": "cpp",
    ".cs": "csharp",
    ".py": "python",
    ".rb": "ruby",
    ".pl": "perl", ".pm": "perl",
    ".sh": "shell", ".bash": "shell",
    ".php": "php",
    ".java": "java",
    ".js": "javascript", ".ts": "typescript",
    ".go": "go",
    ".rs": "rust",
    ".lua": "lua",
    ".asm": "assembly", ".s": "assembly",
    ".ps1": "powershell",
    ".bat": "batch", ".cmd": "batch",
    ".txt": "text", ".md": "text", ".rst": "text",
    ".html": "html", ".xml": "xml",
    ".json": "json", ".yaml": "yaml", ".yml": "yaml",
}


def detect_language_from_path(file_path: str) -> str:
    """Return the probable language based on file extension."""
    ext = Path(file_path).suffix.lower()
    return _EXT_TO_LANG.get(ext, "unknown")


def detect_language_from_content(content: str) -> str:
    """Heuristic language detection from source code content."""
    if not content:
        return "unknown"

    first_line = content.strip().split("\n", 1)[0]

    # Shebang detection
    if first_line.startswith("#!"):
        if "python" in first_line:
            return "python"
        if "ruby" in first_line:
            return "ruby"
        if "perl" in first_line:
            return "perl"
        if "php" in first_line:
            return "php"
        if "bash" in first_line or "/sh" in first_line:
            return "shell"
        if "node" in first_line:
            return "javascript"

    # Structural patterns
    c_patterns = [
        r"#include\s*<", r"#include\s*\"", r"\bint\s+main\s*\(",
        r"\bvoid\s+\w+\s*\(", r"\bchar\s*\*", r"\bprintf\s*\(",
        r"\bmalloc\s*\(", r"\bfree\s*\(", r"#define\s+\w+",
    ]
    if sum(1 for p in c_patterns if re.search(p, content)) >= 2:
        # Distinguish C++ from plain C
        cpp_patterns = [
            r"\bclass\s+\w+", r"\bnamespace\s+\w+",
            r"\btemplate\s*<", r"\bcout\b", r"\bcerr\b",
            r"\bstd::", r"\busing\s+namespace\b",
            r"#include\s*<(iostream|string|vector|map|set|algorithm|memory|fstream)>",
            r"\bnew\s+\w+", r"\bdelete\b",
        ]
        if sum(1 for p in cpp_patterns if re.search(p, content)) >= 2:
            return "cpp"
        return "c"

    # C# detection (must run before Java — both use `class` and access modifiers,
    # but C# has `using` directives and `namespace` blocks).
    csharp_patterns = [
        r"^\s*using\s+[\w.]+;",
        r"^\s*namespace\s+[\w.]+",
        r"\b(public|private|protected|internal)\s+(static\s+)?(class|struct|interface|enum)\b",
        r"\bConsole\.Write",
        r"\bstring\[\]\s+args",
        r"\bvar\s+\w+\s*=",
        r"\bawait\s+",
        r"\basync\s+Task",
    ]
    if sum(1 for p in csharp_patterns if re.search(p, content, re.MULTILINE)) >= 2:
        return "csharp"

    # Java detection (must run BEFORE Python — `import pkg.Class;` also
    # matches the generic Python `import\s+\w+` pattern).
    java_patterns = [
        r"^\s*(import|package)\s+[\w.]+;",
        r"\b(public|private|protected)\s+(static\s+)?(class|interface|enum|void|int|String)",
        r"\bpublic\s+static\s+void\s+main\s*\(",
        r"@(Override|Test|Deprecated|SuppressWarnings)",
        r"System\.out\.print",
        r"\bnew\s+\w+\s*\(",
    ]
    if sum(1 for p in java_patterns if re.search(p, content, re.MULTILINE)) >= 2:
        return "java"

    if re.search(r"\bdef\s+\w+\s*\(|from\s+\w+\s+import|^import\s+\w+\s*$", content, re.MULTILINE):
        return "python"
    if re.search(r"<\?php|echo\s|function\s+\w+\s*\(.*\)\s*{", content):
        return "php"
    if re.search(r"require\s+['\"]|class\s+\w+\s*<|def\s+\w+.*\bend\b", content):
        return "ruby"
    if re.search(r"use\s+strict|my\s+\$|sub\s+\w+\s*\{", content):
        return "perl"

    return "unknown"


def get_file_extension_for_language(language: str) -> str:
    """Map a language name to a file extension (with dot)."""
    mapping = {
        "c": ".c", "cpp": ".cpp", "csharp": ".cs",
        "python": ".py", "ruby": ".rb",
        "perl": ".pl", "shell": ".sh", "php": ".php",
        "java": ".java", "javascript": ".js", "typescript": ".ts",
        "go": ".go", "rust": ".rs", "lua": ".lua",
        "assembly": ".asm", "powershell": ".ps1",
        "text": ".txt", "html": ".html",
    }
    return mapping.get(language, ".txt")


# ---------------------------------------------------------------------------
# File type checks
# ---------------------------------------------------------------------------

def is_text_file(file_path: Path, text_extensions: Optional[Set[str]] = None) -> bool:
    """Return True if *file_path* looks like a text/source file."""
    exts = text_extensions or DEFAULT_TEXT_EXTENSIONS
    if file_path.suffix.lower() in exts:
        return True
    mime, _ = mimetypes.guess_type(str(file_path))
    if mime and mime.startswith("text/"):
        return True
    # Peek into the file
    try:
        data = file_path.read_bytes(1024) if file_path.stat().st_size > 1024 else file_path.read_bytes()
        return b"\x00" not in data
    except Exception:
        return False


def classify_file_type(file_path: str) -> str:
    """Classify a source file path into a category (source, header, test, build, doc, other)."""
    p = file_path.lower()
    if p.endswith((".c", ".cc", ".cpp", ".cxx", ".s", ".S", ".asm", ".java", ".cs")):
        return "source"
    if p.endswith((".h", ".hh", ".hpp", ".hxx")):
        return "header"
    if "/test" in p or "/tests/" in p or p.startswith("test"):
        return "test"
    if p.endswith(("Makefile", ".mk", "CMakeLists.txt", "configure.ac", "configure.in", ".am")):
        return "build"
    if p.endswith((".md", ".rst", ".txt", ".man")):
        return "doc"
    return "other"


# ---------------------------------------------------------------------------
# Content extraction from exploit files
# ---------------------------------------------------------------------------

def extract_file_content(file_path: Path, text_extensions: Optional[Set[str]] = None) -> Tuple[Optional[str], str]:
    """Read and return the text content of a file.

    Returns (content, status) where status is one of:
      ``"success"``, ``"binary"``, ``"too_large"``, ``"error:<msg>"``.
    """
    if not file_path.exists():
        return None, "error:file_not_found"

    if not is_text_file(file_path, text_extensions):
        return None, "binary"

    # Guard against very large files (>5 MB)
    try:
        sz = file_path.stat().st_size
    except OSError:
        return None, "error:stat_failed"

    if sz > 5 * 1024 * 1024:
        return None, "too_large"

    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")
        return content, "success"
    except Exception as exc:
        return None, f"error:{exc}"


def clean_poc_content(content: str) -> Tuple[str, list[str]]:
    """Clean PoC source code – strip comments, trailing whitespace, etc.

    Returns ``(cleaned_content, list_of_applied_transformations)``.
    """
    if not content:
        return content, []

    transforms: list[str] = []
    out = content

    # Normalise line endings
    if "\r\n" in out:
        out = out.replace("\r\n", "\n")
        transforms.append("normalised_crlf")

    # Strip trailing whitespace
    lines = [line.rstrip() for line in out.split("\n")]
    out = "\n".join(lines)
    transforms.append("stripped_trailing_ws")

    # Remove trailing blank lines
    out = out.rstrip("\n") + "\n"
    transforms.append("trimmed_trailing_blanks")

    return out, transforms


def is_valid_poc_content(content: str) -> Tuple[bool, str]:
    """Quick sanity check on PoC content.

    Returns ``(is_valid, reason)`` — the reason is empty when valid.
    """
    if not content or not content.strip():
        return False, "empty_content"
    if len(content.strip()) < 20:
        return False, "too_short"
    if content.strip().startswith("<!DOCTYPE") or content.strip().startswith("<html"):
        return False, "html_page"
    return True, ""
