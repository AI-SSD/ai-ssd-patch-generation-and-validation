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
        if any(sh in first_line for sh in ("bash", "/sh", "tcsh", "/csh", "ksh", "zsh", "dash", "fish")):
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


def is_regression_test_path(file_path: str) -> bool:
    """True when *file_path* looks like a project regression test (C source).

    Project-agnostic but tuned to common conventions: a C source whose basename
    starts with ``tst-``/``test-``/``test_``/``bug-`` (glibc, many GNU projects),
    OR that lives under a ``test``/``tests``/``testsuite`` directory. Used by
    Option A to harvest the reproducer a fixing commit ships. Excludes shell/
    Makefile/headers — only compilable test programs.
    """
    p = file_path.replace("\\", "/").lower()
    if not p.endswith((".c", ".cc", ".cpp", ".cxx")):
        return False
    base = p.rsplit("/", 1)[-1]
    if base.startswith(("tst-", "test-", "test_", "bug-")) or base == "test.c":
        return True
    if "/test/" in p or "/tests/" in p or "/testsuite/" in p:
        return True
    return False


def _subdir_from_makefile_guard(test_name_re: "re.Pattern", content: str) -> str:
    """Return the build subdir from an ``ifeq ($(subdir),X)`` guard enclosing the
    test, else "".

    glibc's sysdeps Makefile *fragments* are included into the build of a
    top-level subdir, and scope their additions with ``ifeq ($(subdir),math)``
    style guards. The fragment lives at e.g. ``sysdeps/ieee754/ldbl-96/Makefile``
    but the test is actually built under ``math`` — which is exactly the
    ``$(subdir)`` value in the guard. So when the test name appears inside such a
    block, that guard value is the authoritative build subdir. Tracks all
    ``if*``/``endif`` nesting to find the nearest enclosing subdir guard.
    """
    guard = re.compile(r"^\s*ifeq\s*\(\s*\$\(subdir\)\s*,\s*([\w./-]+)\s*\)")
    cond = re.compile(r"^\s*if(eq|neq|def|ndef)\b")
    endif = re.compile(r"^\s*endif\b")
    stack: "list[Optional[str]]" = []
    for line in content.splitlines():
        g = guard.match(line)
        if g:
            stack.append(g.group(1))
        elif cond.match(line):
            stack.append(None)
        elif endif.match(line) and stack:
            stack.pop()
        if test_name_re.search(line):
            for s in reversed(stack):
                if s:
                    return s
    return ""


def resolve_test_build_subdir(
    test_name: str,
    makefile_contents: "list[Tuple[str, str]]",
    default_subdir: str,
) -> str:
    """Resolve the build subdir that *registers* ``test_name``.

    A make-based project registers a test by listing its name in a Makefile
    variable (glibc: ``tests += foo``); the build subdir is then either the
    directory of THAT Makefile, or — for a sysdeps *fragment* — the top-level
    subdir named in an enclosing ``ifeq ($(subdir),X)`` guard. Neither is the
    naive ``path.split('/')[0]``: glibc registers ``sysdeps/.../test-foo.c`` in
    ``sysdeps/.../Makefile`` under ``ifeq ($(subdir),math)``, so the test builds
    as ``math`` and every ``make test t=sysdeps/...`` call otherwise fails with
    "No rule to make target".

    Resolution order, over the fixing commit's changed Makefiles
    (``makefile_contents`` is a list of ``(path, content)``):
      1. an ``ifeq ($(subdir),X)`` guard enclosing the test → X (authoritative);
      2. the Makefile's own directory, preferring one with a ``tests`` assignment;
      3. ``default_subdir``.
    Generic to make-based projects; the only assumed conventions are the
    near-universal ``test(s)`` variable and glibc's ``$(subdir)`` guard idiom
    (harmless where absent).
    """
    name = (test_name or "").strip()
    if not name:
        return default_subdir
    word = re.compile(r"(?<![\w.-])" + re.escape(name) + r"(?![\w.-])")
    tests_var = re.compile(r"^\s*[\w-]*tests?[\w-]*\s*[:+]?=", re.MULTILINE | re.IGNORECASE)
    weak: Optional[str] = None
    for path, content in (makefile_contents or []):
        if not content or not word.search(content):
            continue
        guarded = _subdir_from_makefile_guard(word, content)
        if guarded:
            return guarded
        norm = path.replace("\\", "/")
        subdir = norm.rsplit("/", 1)[0] if "/" in norm else ""
        if tests_var.search(content):
            return subdir
        if weak is None:
            weak = subdir
    return weak if weak is not None else default_subdir


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


# Anchors that indicate runnable code or commands (vs a prose write-up). Generic
# across the common PoC languages; used only to rescue/exclude doc-extension files.
_POC_CODE_ANCHORS = re.compile(
    r"#\s*include\b"                                   # C / C++
    r"|\b(?:int|void)\s+main\s*\("                     # C main()
    r"|^\s*def\s+\w+\s*\("                             # python def
    r"|^\s*(?:from\s+[\w.]+\s+)?import\s+\w"           # python import
    r"|#!\s*/"                                          # shebang (sh/py/perl/...)
    r"|<\?php"                                          # php
    r"|\bclass\s+\w+\s*[:({]"                          # class decl
    r"|\b(?:php|python[23]?|perl|ruby|node|bash|sh)\s+-[a-z]\b"  # interpreter one-liner
    r"|\b(?:gcc|clang|cc|make|nasm)\b",               # build commands
    re.MULTILINE | re.IGNORECASE,
)
# Doc/prose-prone extensions: a PoC stored as one of these must carry code anchors
# to count as runnable (ExploitDB frequently files write-ups as .txt).
_PROSE_EXTS = {"", ".txt", ".md", ".rst", ".html", ".htm"}
_CVE_ID_RE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)


def classify_poc_runnability(
    content: Optional[str], file_path: str = "", mapped_cve_id: str = "",
) -> Tuple[bool, str]:
    """Decide whether a mapped PoC is a *runnable* reproducer vs a prose write-up
    or a mis-mapped entry. Returns ``(runnable, reason)`` (reason empty when ok).

    Three checks, project-agnostic:
      1. basic validity (empty / too short / HTML page) via is_valid_poc_content;
      2. **CVE-ID mismatch** — the text cites CVE-IDs but not the one it was mapped
         to (e.g. an ExploitDB ``codes`` column tags CVE-A while the write-up is
         about CVE-B) → not a PoC for *this* CVE;
      3. **write-up with no code** — a doc-extension file (.txt/.md/...) that
         carries no runnable code/command anchors is a description, not a PoC.
    Real source extensions (.c/.py/.sh/...) are trusted as code.
    """
    ok, reason = is_valid_poc_content(content or "")
    if not ok:
        return False, reason
    text = content or ""
    if mapped_cve_id:
        cited = {c.upper() for c in _CVE_ID_RE.findall(text)}
        if cited and mapped_cve_id.upper() not in cited:
            return False, "cve_id_mismatch:" + sorted(cited)[0]
    base = file_path.replace("\\", "/").rsplit("/", 1)[-1]
    ext = ("." + base.rsplit(".", 1)[1].lower()) if "." in base else ""
    if ext in _PROSE_EXTS and not _POC_CODE_ANCHORS.search(text):
        return False, "writeup_no_runnable_code"
    return True, ""
