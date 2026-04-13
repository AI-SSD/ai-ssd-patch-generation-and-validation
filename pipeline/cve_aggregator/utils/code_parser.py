"""
Code parsing utilities for the CVE Aggregator pipeline.

Language-aware extraction of functions, methods, macros, and other code
units from source files.  Currently supports **C**, **C++**, **C#**, and **Java**.

Ported from the reference ``extract_patches.py`` implementation for
robust function-level extraction and comparison.
"""

from __future__ import annotations

import re
import logging
from typing import Dict, List

logger = logging.getLogger(__name__)

# Keywords that look like function calls but are control-flow statements
_CONTROL_FLOW_KEYWORDS = {
    "if", "else", "while", "for", "do", "switch", "case",
    "default", "return", "break", "continue", "goto",
}


# ---------------------------------------------------------------------------
# Stripping helpers (for comparison purposes)
# ---------------------------------------------------------------------------

def strip_code_for_comparison(code: str) -> str:
    """Strip C comments and normalise whitespace so two code strings can be
    compared ignoring cosmetic differences (comments, indentation, blank lines).
    """
    if not code:
        return ""
    # 1. Remove C-style multi-line comments /* … */
    out = re.sub(r"/\*.*?\*/", "", code, flags=re.DOTALL)
    # 2. Remove C++ style single-line comments // …
    out = re.sub(r"//.*", "", out)
    # 3. Collapse all whitespace into a single space
    out = re.sub(r"\s+", " ", out)
    return out.strip()


# ---------------------------------------------------------------------------
# C function extraction  (robust version from extract_patches.py)
# ---------------------------------------------------------------------------

# Regex that matches the start of a C function definition.
# Group 1 – optional return-type qualifiers; Group 2 – function name (may
# have a leading ``*``).
_FUNCTION_SIGNATURE_RE = re.compile(
    r"\b("
    r"(?:static|extern|inline|const|volatile|unsigned|signed|"
    r"struct|enum|union|void|int|char|short|long|float|double|"
    r"size_t|ssize_t|uint\w*|int\w*|bool|FILE|pthread_\w+|\w+_t)"
    r"\s+)*"                       # return type (optional qualifiers + type)
    r"(\*?\s*\w+)\s*"             # function name (may have pointer star)
    r"\([^)]*\)\s*"               # parameter list
    r"\{",                         # opening brace
    re.MULTILINE,
)


def extract_c_functions(content: str) -> Dict[str, str]:
    """Extract C function definitions from *content*.

    Returns ``{function_name: full_function_text}`` including the
    signature and the full body (up to the matching ``}``).

    Uses the robust regex and brace-matching approach from
    ``extract_patches.py``.
    """
    functions: Dict[str, str] = {}

    for match in _FUNCTION_SIGNATURE_RE.finditer(content):
        try:
            f_name_raw = match.group(2)
            if not f_name_raw:
                continue
            f_name = f_name_raw.strip().lstrip("*").strip()

            # Skip control-flow keywords that look like function calls
            if f_name in _CONTROL_FLOW_KEYWORDS:
                continue

            # Function names must be valid C identifiers
            if not re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*$", f_name):
                continue

            signature_start = match.start()
            brace_pos = match.end() - 1  # the '{' character

            # Walk forward to find the matching closing brace
            depth = 1
            i = brace_pos + 1
            while i < len(content) and depth > 0:
                ch = content[i]
                if ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                elif ch == '"':
                    # skip string literal
                    i += 1
                    while i < len(content) and content[i] != '"':
                        if content[i] == "\\":
                            i += 1
                        i += 1
                elif ch == "'":
                    # skip char literal
                    i += 1
                    while i < len(content) and content[i] != "'":
                        if content[i] == "\\":
                            i += 1
                        i += 1
                i += 1

            if depth == 0:
                body = content[signature_start:i].strip()
                if f_name not in functions:
                    functions[f_name] = body

        except (IndexError, AttributeError):
            continue

    return functions


# ---------------------------------------------------------------------------
# C macro extraction  (from extract_patches.py)
# ---------------------------------------------------------------------------

_MACRO_BLOCK_RE = re.compile(
    r"^\s*#define\s+([\w]+(?:[\w,()\s]*?))"   # macro name (+ optional params)
    r"(\s*(?:[^\n]*\\\n)*[^\n]*)\s*",         # macro body (continuation lines)
    re.MULTILINE,
)


def extract_c_macros(content: str) -> Dict[str, str]:
    """Extract ``#define`` macros that span multiple lines or contain
    non-trivial code (braces, semicolons).
    """
    macros: Dict[str, str] = {}

    for match in _MACRO_BLOCK_RE.finditer(content):
        m_name_raw = match.group(1).strip()
        m_name = m_name_raw.split("(")[0].strip()

        define_line_start = content.rfind("\n", 0, match.start()) + 1
        macro_code = content[define_line_start : match.end()].strip()

        # Only keep macros with non-trivial bodies
        if "\n" in macro_code or re.search(r"[{;]", strip_code_for_comparison(macro_code)):
            if m_name not in macros:
                macros[m_name] = macro_code

    return macros


def extract_all_code_units(content: str) -> Dict[str, Dict[str, str]]:
    """Extract both functions and macros from C source.

    Returns ``{"functions": {…}, "macros": {…}}``.
    """
    return {
        "functions": extract_c_functions(content),
        "macros": extract_c_macros(content),
    }


# ---------------------------------------------------------------------------
# Changed-unit detection  (ported from extract_patches.py)
# ---------------------------------------------------------------------------

def find_changed_units(
    vuln_content: str,
    patched_content: str,
    *,
    file_path: str | None = None,
) -> List[Dict[str, str]]:
    """Compare vulnerable and patched file contents and return a list of
    code units (functions / macros / methods) that were **actually modified**
    (i.e. more than just comments or whitespace changes).

    When *file_path* is provided, the language is inferred from its
    extension so the correct extractor is used (C or Java).

    Each returned dict has keys:
        ``name``, ``unit_type`` ("function" | "macro" | "method"),
        ``vuln_body``, ``patched_body``.
    """
    language = _infer_language(file_path)

    if language in ("java", "csharp"):
        extractor = extract_java_methods if language == "java" else extract_csharp_methods
        v_units = extractor(vuln_content or "")
        p_units = extractor(patched_content or "")
        all_names = sorted(set(v_units.keys()) | set(p_units.keys()))
        changed: List[Dict[str, str]] = []
        for name in all_names:
            v_code = v_units.get(name, "")
            p_code = p_units.get(name, "")
            if strip_code_for_comparison(v_code) != strip_code_for_comparison(p_code):
                changed.append({
                    "name": name,
                    "unit_type": "method",
                    "vuln_body": v_code,
                    "patched_body": p_code,
                })
        return changed

    # Default: C / C++ extraction (C++ reuses C function + macro extractors)
    v_funcs = extract_c_functions(vuln_content or "")
    p_funcs = extract_c_functions(patched_content or "")
    v_macros = extract_c_macros(vuln_content or "")
    p_macros = extract_c_macros(patched_content or "")

    v_units = {**v_funcs, **v_macros}
    p_units = {**p_funcs, **p_macros}

    all_names = sorted(set(v_units.keys()) | set(p_units.keys()))
    changed: List[Dict[str, str]] = []

    for name in all_names:
        unit_type = "macro" if (name in v_macros or name in p_macros) else "function"
        v_code = v_units.get(name, "")
        p_code = p_units.get(name, "")

        if strip_code_for_comparison(v_code) != strip_code_for_comparison(p_code):
            changed.append({
                "name": name,
                "unit_type": unit_type,
                "vuln_body": v_code,
                "patched_body": p_code,
            })

    return changed


def extract_functions_from_file(content: str, file_path: str) -> List[Dict[str, str]]:
    """Return a list of ``{name, body, file_path}`` dicts for each function/method.

    Dispatches to the correct language extractor based on *file_path* extension.
    """
    ext = file_path.rsplit(".", 1)[-1].lower() if "." in file_path else ""
    if ext == "java":
        funcs = extract_java_methods(content)
    elif ext == "cs":
        funcs = extract_csharp_methods(content)
    else:
        # C and C++ both use the C extractor
        funcs = extract_c_functions(content)

    results: List[Dict[str, str]] = []
    for name, body in funcs.items():
        results.append({
            "name": name,
            "body": body,
            "file_path": file_path,
        })
    return results


# ---------------------------------------------------------------------------
# Java method / class extraction
# ---------------------------------------------------------------------------

# Regex that matches Java method declarations (inside a class body).
# Captures:
#   - Optional annotations on the same line (simplified)
#   - Access modifiers + return type + method name + param list + '{'
_JAVA_METHOD_SIGNATURE_RE = re.compile(
    r"(?:@\w+(?:\([^)]*\))?\s+)*"           # optional annotations
    r"(?:(?:public|private|protected|static|final|abstract|"
    r"synchronized|native|default|strictfp)\s+)*"  # modifiers
    r"(?:<[^>]+>\s+)?"                        # optional generic type params
    r"(?:[\w\[\]<>,\s?]+)\s+"                 # return type (may be generic)
    r"(\w+)\s*"                               # method name (group 1)
    r"\([^)]*\)\s*"                           # parameter list
    r"(?:throws\s+[\w,\s]+)?\s*"             # optional throws clause
    r"\{",                                    # opening brace
    re.MULTILINE,
)

# Control-flow keywords that look like method calls in Java
_JAVA_CONTROL_KEYWORDS = {
    "if", "else", "while", "for", "do", "switch", "case",
    "default", "return", "break", "continue", "throw",
    "try", "catch", "finally", "synchronized", "assert",
    "new",
}


def extract_java_methods(content: str) -> Dict[str, str]:
    """Extract Java method definitions from *content*.

    Returns ``{method_name: full_method_text}`` including the signature
    and the full body (up to the matching ``}``).

    Uses the same brace-matching approach as ``extract_c_functions``.
    """
    methods: Dict[str, str] = {}

    for match in _JAVA_METHOD_SIGNATURE_RE.finditer(content):
        try:
            m_name = match.group(1)
            if not m_name:
                continue

            # Skip control-flow keywords that look like method calls
            if m_name in _JAVA_CONTROL_KEYWORDS:
                continue

            # Method names must be valid Java identifiers
            if not re.match(r"^[a-zA-Z_$][a-zA-Z0-9_$]*$", m_name):
                continue

            signature_start = match.start()
            brace_pos = match.end() - 1  # the '{' character

            # Walk forward to find the matching closing brace
            depth = 1
            i = brace_pos + 1
            while i < len(content) and depth > 0:
                ch = content[i]
                if ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                elif ch == '"':
                    # skip string literal
                    i += 1
                    while i < len(content) and content[i] != '"':
                        if content[i] == "\\":
                            i += 1
                        i += 1
                elif ch == "'":
                    # skip char literal
                    i += 1
                    while i < len(content) and content[i] != "'":
                        if content[i] == "\\":
                            i += 1
                        i += 1
                i += 1

            if depth == 0:
                body = content[signature_start:i].strip()
                if m_name not in methods:
                    methods[m_name] = body

        except (IndexError, AttributeError):
            continue

    return methods


def extract_all_java_units(content: str) -> Dict[str, Dict[str, str]]:
    """Extract Java methods from source.

    Returns ``{"functions": {…}, "macros": {}}``.
    (Java has no macros; the key is kept for API consistency with C.)
    """
    return {
        "functions": extract_java_methods(content),
        "macros": {},
    }


# ---------------------------------------------------------------------------
# C# method extraction
# ---------------------------------------------------------------------------

# Regex that matches C# method declarations.
_CSHARP_METHOD_SIGNATURE_RE = re.compile(
    r"(?:(?:\[[\w.]+(?:\([^)]*\))?\]\s+)*)"   # optional attributes
    r"(?:(?:public|private|protected|internal|static|virtual|override|"
    r"abstract|sealed|async|partial|extern|new|unsafe)\s+)*"  # modifiers
    r"(?:[\w\[\]<>,\s?]+)\s+"                  # return type (may be generic)
    r"(\w+)\s*"                                # method name (group 1)
    r"\([^)]*\)\s*"                            # parameter list
    r"(?:where\s+\w+\s*:\s*[\w,\s]+)?\s*"    # optional generic constraints
    r"\{",                                     # opening brace
    re.MULTILINE,
)

_CSHARP_CONTROL_KEYWORDS = {
    "if", "else", "while", "for", "do", "switch", "case",
    "default", "return", "break", "continue", "throw",
    "try", "catch", "finally", "lock", "using", "foreach",
    "checked", "unchecked", "fixed", "new",
}


def extract_csharp_methods(content: str) -> Dict[str, str]:
    """Extract C# method definitions from *content*.

    Returns ``{method_name: full_method_text}`` including the signature
    and the full body (up to the matching ``}``).
    """
    methods: Dict[str, str] = {}

    for match in _CSHARP_METHOD_SIGNATURE_RE.finditer(content):
        try:
            m_name = match.group(1)
            if not m_name:
                continue

            if m_name in _CSHARP_CONTROL_KEYWORDS:
                continue

            if not re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*$", m_name):
                continue

            signature_start = match.start()
            brace_pos = match.end() - 1

            depth = 1
            i = brace_pos + 1
            while i < len(content) and depth > 0:
                ch = content[i]
                if ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                elif ch == '"':
                    # Handle verbatim strings @"..."
                    if i > 0 and content[i - 1] == "@":
                        i += 1
                        while i < len(content):
                            if content[i] == '"':
                                if i + 1 < len(content) and content[i + 1] == '"':
                                    i += 1  # escaped quote in verbatim string
                                else:
                                    break
                            i += 1
                    else:
                        i += 1
                        while i < len(content) and content[i] != '"':
                            if content[i] == "\\":
                                i += 1
                            i += 1
                elif ch == "'":
                    i += 1
                    while i < len(content) and content[i] != "'":
                        if content[i] == "\\":
                            i += 1
                        i += 1
                i += 1

            if depth == 0:
                body = content[signature_start:i].strip()
                if m_name not in methods:
                    methods[m_name] = body

        except (IndexError, AttributeError):
            continue

    return methods


def extract_all_csharp_units(content: str) -> Dict[str, Dict[str, str]]:
    """Extract C# methods from source.

    Returns ``{"functions": {…}, "macros": {}}``.
    """
    return {
        "functions": extract_csharp_methods(content),
        "macros": {},
    }


# ---------------------------------------------------------------------------
# Language-dispatched helpers
# ---------------------------------------------------------------------------

def _infer_language(file_path: str | None) -> str:
    """Infer language from a file path extension."""
    if not file_path:
        return "c"
    ext = file_path.rsplit(".", 1)[-1].lower() if "." in file_path else ""
    return {
        "java": "java", "py": "python", "rb": "ruby",
        "cpp": "cpp", "cc": "cpp", "cxx": "cpp", "hpp": "cpp", "hxx": "cpp",
        "cs": "csharp",
    }.get(ext, "c")


def extract_all_units(content: str, *, language: str = "c") -> Dict[str, Dict[str, str]]:
    """Language-aware extraction of code units.

    Falls back to C extraction for unrecognised languages.
    """
    if language == "java":
        return extract_all_java_units(content)
    if language == "csharp":
        return extract_all_csharp_units(content)
    # C++ reuses C extractors (functions + macros)
    return extract_all_code_units(content)
