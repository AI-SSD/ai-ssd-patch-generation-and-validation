"""
C / C-like code parsing utilities for the CVE Aggregator pipeline.

Extract functions, macros, and other code units from source files.
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
) -> List[Dict[str, str]]:
    """Compare vulnerable and patched file contents and return a list of
    code units (functions / macros) that were **actually modified** (i.e.
    more than just comments or whitespace changes).

    Each returned dict has keys:
        ``name``, ``unit_type`` ("function" | "macro"),
        ``vuln_body``, ``patched_body``.
    """
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
    """Return a list of ``{name, body, file_path}`` dicts for each function."""
    results: List[Dict[str, str]] = []
    for name, body in extract_c_functions(content).items():
        results.append({
            "name": name,
            "body": body,
            "file_path": file_path,
        })
    return results
