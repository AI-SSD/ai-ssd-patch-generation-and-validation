"""
CVE Patch Extractor for Glibc Vulnerabilities - Git-based Version

This script uses GitPython to directly extract FULL vulnerable and patched code 
from git commits, eliminating the need for web scraping. It now also extracts 
and compares individual C functions AND multi-line MACROS to generate a 
separate function-level dataset.

Key Features:
- Processes each unique P_COMMIT only once (deduplicates commits)
- Extracts ALL .c files from each commit, regardless of FilePath
- Aggregates all code changes from multiple .c files in the same commit
- Adds V_COMMIT column storing the parent commit (vulnerability commit)
- Generates a separate dataset containing only modified functions 
  and modified multi-line macros (like the 'BODY' macro).
- Filters out function/macro units where only comments or whitespace have changed.

Requirements:
- pandas
- gitpython
"""

import pandas as pd
import git
import os
import csv
import re
import difflib
from typing import Optional, Dict, List, Tuple

# Configuration
# Updated CSV_FILENAME to the uploaded file name
CSV_FILENAME = "dump-glibc.csv"
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
FULL_FILE_OUTPUT_FILE = os.path.join(SCRIPT_DIR, "file_dataset.csv")
FUNCTION_OUTPUT_FILE = os.path.join(SCRIPT_DIR, "function_dataset.csv")

GLIBC_REPO_URL = "https://github.com/bminor/glibc.git"
REPO_CACHE_DIR = os.path.join(SCRIPT_DIR, "glibc_repo")


def strip_code_for_comparison(code: str) -> str:
    """
    Strips C-style comments and normalizes whitespace for comparison purposes.
    This is used to identify units where only comments or indentation changed.
    
    Args:
        code: The source code string.
        
    Returns:
        Code string with comments and excessive whitespace removed.
    """
    if not code:
        return ""
    
    # 1. Remove C-style multi-line comments /* ... */
    # The DOTALL flag ensures it works across multiple lines.
    code = re.sub(r'/\*.*?\*/', '', code, flags=re.DOTALL)
    
    # 2. Remove C++ style single-line comments // ...
    code = re.sub(r'//.*', '', code)
    
    # 3. Remove backslash line continuations inside macros, but be careful not to remove 
    # backslashes used for strings or character literals. For now, rely on 
    # step 4 to collapse the resulting whitespace after a backslash/newline pair.

    # 4. Collapse all remaining whitespace (spaces, newlines, tabs) into a single space
    # This step effectively removes indentation and empty lines.
    code = re.sub(r'\s+', ' ', code)
    
    return code.strip()


def extract_c_functions(code: str) -> Dict[str, str]:
    """
    Extracts C function definitions (name and body) from a source code string.
    Uses regex to find the signature and a simple brace-counting mechanism 
    to robustly capture the function body.
    
    Only extracts actual function definitions, NOT control flow structures
    like while, if, for, switch, etc.
    
    Args:
        code: The full source code content as a string.
        
    Returns:
        Dictionary mapping {function_name: full_function_code_string}.
    """
    functions = {}
    
    CONTROL_FLOW_KEYWORDS = {
        'if', 'else', 'while', 'for', 'do', 'switch', 'case', 
        'default', 'return', 'break', 'continue', 'goto'
    }
    
    # Corrected regex pattern to robustly match function signatures 
    FUNCTION_SIGNATURE_PATTERN = re.compile(
        r'\b((?:static|extern|inline|const|volatile|unsigned|signed|struct|enum|union|void|int|char|short|long|float|double|size_t|ssize_t|uint\w*|int\w*|bool|FILE|pthread_\w+|\w+_t)\s+)*'  # Return type (optional qualifiers + type)
        r'(\*?\s*\w+)\s*'  # Function name (may have pointer)
        r'\([^)]*\)\s*'  # Parameters: Matches (params) 
        r'\{',  # Opening brace
        re.MULTILINE
    )
    
    for match in FUNCTION_SIGNATURE_PATTERN.finditer(code):
        try:
            # Extract the function name from group 2, removing any pointer/whitespace
            f_name_raw = match.group(2)
            if not f_name_raw:
                continue
                
            f_name = f_name_raw.strip().lstrip('*').strip()
            
            # Skip if this is a control flow keyword, not a function
            if f_name in CONTROL_FLOW_KEYWORDS:
                continue
            
            # Additional validation: function names should be valid C identifiers
            if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', f_name):
                continue
            
            signature_start_index = match.start()
            
            # Start scanning from the opening brace index
            body_start_index = match.end() - 1  # The { character
            
            balance = 1
            i = body_start_index + 1
            
            # Robust brace matching to find the end of the function body
            while i < len(code):
                char = code[i]
                if char == '{':
                    balance += 1
                elif char == '}':
                    balance -= 1
                
                if balance == 0:
                    # Found the matching closing brace
                    f_body = code[signature_start_index:i+1].strip()
                    
                    if f_name not in functions:
                        functions[f_name] = f_body
                    break
                i += 1
        except (IndexError, AttributeError):
            continue
            
    return functions

def extract_c_macros(code: str) -> Dict[str, str]:
    """
    Extracts multi-line C macro definitions, especially those containing complex 
    code bodies (like the user's BODY example).
    
    The pattern uses negative lookbehind (?<!\\) to stop capturing content 
    only when a newline is NOT preceded by a backslash, effectively capturing 
    the entire definition block including line continuations.
    
    Args:
        code: The full source code content as a string.
        
    Returns:
        Dictionary mapping {macro_name: full_macro_code_string}.
    """
    macros = {}
    
    # Pattern: 
    # ^\s*#define\s+([\w]+)\s* -> Match #define and capture the name (Group 1)
    # (.*?)                     -> Non-greedy capture of content (Group 2)
    # (?<!\\)\n                 -> Stop when a newline is found that is NOT preceded by a backslash
    MACRO_BLOCK_PATTERN = re.compile(
        r'^\s*#define\s+([\w]+)\s*(.*?)(?<!\\)\n',
        re.MULTILINE | re.DOTALL
    )

    for match in MACRO_BLOCK_PATTERN.finditer(code):
        m_name = match.group(1)
        
        # Determine the start of the line containing #define to capture the full definition line
        define_line_start = code.rfind('\n', 0, match.start()) + 1
        
        # The full macro code is from the start of the #define line up to the end of the match
        macro_code = code[define_line_start:match.end()].strip()
        macros[m_name] = macro_code

    return macros


def generate_changes_diff(v_code: str, p_code: str) -> str:
    """
    Generates a unified diff string between the vulnerable and patched code unit.
    
    Args:
        v_code: Vulnerable code string.
        p_code: Patched code string.
        
    Returns:
        Unified diff string (empty if no changes found).
    """
    v_lines = v_code.splitlines(keepends=True)
    p_lines = p_code.splitlines(keepends=True)
    
    # Generate unified diff, excluding timestamps and file paths for cleaner output
    diff = difflib.unified_diff(
        v_lines, 
        p_lines, 
        fromfile='vulnerable', 
        tofile='patched', 
        lineterm=''
    )
    
    # Join diff lines into a single string
    return "".join(diff)

def get_function_level_changes(full_df: pd.DataFrame) -> pd.DataFrame:
    """
    Analyzes the full file dataset to extract and compare individual C functions
    AND multi-line C macros that have been modified, generating the function-level dataset.
    
    Uses stripped code for comparison filtering but generates output using the original code.
    
    Args:
        full_df: The DataFrame generated by the main extraction process, 
                 containing V_CODE and P_CODE columns.
        
    Returns:
        DataFrame containing only the modified code units with required columns.
    """
    function_results = []
    
    print("\nStarting function/macro-level analysis (filtering comment/whitespace changes)...")
    
    for idx, row in full_df.iterrows():
        cve_id = row['CVE']
        v_commit = row['V_COMMIT']
        p_commit = row['P_COMMIT']
        file_path = row['FilePath']
        v_full_code = row['V_CODE']
        p_full_code = row['P_CODE']
        
        # 1. Extract Functions
        v_funcs = extract_c_functions(v_full_code)
        p_funcs = extract_c_functions(p_full_code)
        
        # 2. Extract Macros
        v_macros = extract_c_macros(v_full_code)
        p_macros = extract_c_macros(p_full_code)
        
        # 3. Combine Functions and Macros into one dictionary for comparison
        v_units = {**v_funcs, **v_macros}
        p_units = {**p_funcs, **p_macros}
        
        # Combine all unique unit names found in both versions
        all_unit_names = set(v_units.keys()) | set(p_units.keys())
        
        for unit_name in sorted(list(all_unit_names)):
            v_unit_code = v_units.get(unit_name, "")
            p_unit_code = p_units.get(unit_name, "")
            
            # 4. Compare stripped code to filter out comment/whitespace-only changes
            v_unit_code_stripped = strip_code_for_comparison(v_unit_code)
            p_unit_code_stripped = strip_code_for_comparison(p_unit_code)
            
            if v_unit_code_stripped != p_unit_code_stripped:
                # Code unit was modified by logical content
                
                # 5. Generate the diff string using the ORIGINAL code (to keep full context)
                changes_diff = generate_changes_diff(v_unit_code, p_unit_code)
                
                # 6. Append to results
                function_results.append({
                    'CVE': cve_id,
                    'V_COMMIT': v_commit,
                    'P_COMMIT': p_commit,
                    'FilePath': file_path,
                    'F_NAME': unit_name,
                    'V_FUNCTION': v_unit_code,
                    'P_FUNCTION': p_unit_code,
                    'CHANGES': changes_diff
                })

    print(f"Function/Macro-level analysis complete. Found {len(function_results)} modified code units (excluding comment/whitespace-only changes).")
    if not function_results:
        return pd.DataFrame()
        
    results_df = pd.DataFrame(function_results)
    
    return results_df[['CVE', 'V_COMMIT', 'P_COMMIT', 'FilePath', 'F_NAME', 'V_FUNCTION', 'P_FUNCTION', 'CHANGES']]


def fetch_csv_data_from_local(filename: str) -> pd.DataFrame:
    """
    Read and parse a CSV file located in the same directory as this script.
    
    Args:
        filename: Name of the CSV file in the script directory
        
    Returns:
        DataFrame containing the CSV data
    """
    script_dir = os.path.dirname(os.path.abspath(__file__))
    csv_path = os.path.join(script_dir, filename)
    
    print(f"Reading CSV from local file: {csv_path}")
    
    if not os.path.exists(csv_path):
        raise FileNotFoundError(f"CSV file not found at: {csv_path}")
    
    df = pd.read_csv(csv_path)
    print(f"Loaded {len(df)} rows from CSV")
    print(f"Columns: {df.columns.tolist()}")
    return df


def setup_git_repository(repo_path: str, repo_url: str) -> git.Repo:
    """
    Clone or open the glibc git repository.
    
    Args:
        repo_path: Local path where repository should be stored
        repo_url: URL of the git repository
        
    Returns:
        GitPython Repo object
    """
    if os.path.exists(repo_path):
        print(f"Opening existing repository at {repo_path}")
        repo = git.Repo(repo_path)
        
        # Fetch latest changes
        print("Fetching latest changes from remote...")
        try:
            origin = repo.remotes.origin
            origin.fetch()
            print("Repository updated successfully")
        except Exception as e:
            print(f"Warning: Could not fetch updates: {e}")
    else:
        print(f"Cloning repository from {repo_url} to {repo_path}")
        print("This may take several minutes for the first run...")
        repo = git.Repo.clone_from(repo_url, repo_path)
        print("Repository cloned successfully")
    
    return repo


def get_full_file_content(repo: git.Repo, commit_hash: str, file_path: str) -> Optional[str]:
    """
    Get the full content of a file at a specific commit.
    
    Args:
        repo: GitPython Repo object
        commit_hash: The commit hash
        file_path: Path to the file in the repository
        
    Returns:
        Full file content as string, or None if file doesn't exist
    """
    try:
        commit = repo.commit(commit_hash)
        # Use git show to get file content at specific commit
        file_content = (commit.tree / file_path).data_stream.read()
        return file_content.decode('utf-8', errors='ignore')
    except (KeyError, AttributeError):
        # File doesn't exist at this commit
        return None
    except Exception as e:
        print(f"Error reading file {file_path} at commit {commit_hash}: {e}")
        return None


def extract_all_c_files_from_commit(repo: git.Repo, commit_hash: str) -> Tuple[Optional[str], List[Dict]]:
    """
    Extract FULL vulnerable and patched code from ALL .c files in a git commit.
    Gets the complete file content before and after the commit for every .c file.
    
    Args:
        repo: GitPython Repo object
        commit_hash: The commit hash to analyze (P_COMMIT)
        
    Returns:
        Tuple: (V_COMMIT hash, List of dicts with file_path, vulnerable_code, patched_code)
    """
    print(f"Processing commit hash: {commit_hash}")
    
    v_commit_hash: Optional[str] = None
    
    try:
        # Get the commit object (P_COMMIT)
        commit = repo.commit(commit_hash)
        
        # Get parent commit (the vulnerable version - V_COMMIT)
        if not commit.parents:
            print(f"Commit {commit_hash} has no parents (initial commit), skipping...")
            return None, []
        
        parent_commit = commit.parents[0]
        v_commit_hash = parent_commit.hexsha
        print(f"Parent commit (V_COMMIT): {v_commit_hash}")
        
        # Get the diff to find which files were modified
        diffs = parent_commit.diff(commit)
        
        print(f"Found {len(diffs)} file(s) changed in commit")
        
        results = []
        c_files_found = 0
        
        for diff_item in diffs:
            # Get the file path
            file_path = diff_item.b_path or diff_item.a_path
            
            if not file_path:
                continue
            
            if not file_path.endswith('.c'):
                print(f"  Skipping {file_path} (not a .c file)")
                continue
            
            c_files_found += 1
            
            # Get FULL file content from parent commit (vulnerable version)
            vulnerable_code = get_full_file_content(repo, v_commit_hash, file_path)
            
            # Get FULL file content from current commit (patched version)
            patched_code = get_full_file_content(repo, commit.hexsha, file_path)
            
            # Handle file additions/deletions
            if vulnerable_code is None and patched_code is not None:
                print(f"  ℹ {file_path}: New file added (no vulnerable version)")
                vulnerable_code = ""
            elif vulnerable_code is not None and patched_code is None:
                print(f"  ℹ {file_path}: File deleted (no patched version)")
                patched_code = ""
            elif vulnerable_code is None and patched_code is None:
                print(f"  Skipping {file_path} (file not found in either version)")
                continue
            
            result = {
                'file_path': file_path,
                'vulnerable_code': vulnerable_code,
                'patched_code': patched_code
            }
            results.append(result)
            
            vuln_lines = len(vulnerable_code.splitlines()) if vulnerable_code else 0
            patch_lines = len(patched_code.splitlines()) if patched_code else 0
            
            print(f"  ✓ {file_path}:")
            print(f"    - Vulnerable version: {vuln_lines} lines (at {v_commit_hash[:7]})")
            print(f"    - Patched version: {patch_lines} lines (at {commit_hash[:7]})")
        
        print(f"Extracted {len(results)} .c file(s) from commit (found {c_files_found} total .c files)")
        return v_commit_hash, results
    
    except git.exc.BadName:
        print(f"Error: Commit {commit_hash} not found in repository")
        return None, []
    except Exception as e:
        print(f"Error processing commit {commit_hash}: {e}")
        import traceback
        traceback.print_exc()
        return None, []


def group_cves_by_commit(df: pd.DataFrame) -> Dict[str, List[str]]:
    """
    Group CVE IDs by their P_COMMIT hash to avoid processing the same commit multiple times.
    
    Args:
        df: DataFrame with CVE and P_COMMIT columns
        
    Returns:
        Dictionary mapping commit_hash -> list of CVE IDs
    """
    commit_to_cves = {}
    
    for _, row in df.iterrows():
        commit_hash = row.get('P_COMMIT')
        cve_id = row.get('CVE')
        
        # Skip invalid entries
        if pd.isna(commit_hash) or not commit_hash or commit_hash == '\\N':
            continue
        if pd.isna(cve_id) or not cve_id:
            continue
        
        if commit_hash not in commit_to_cves:
            commit_to_cves[commit_hash] = []
        
        # Add CVE to this commit's list (avoid duplicates)
        if cve_id not in commit_to_cves[commit_hash]:
            commit_to_cves[commit_hash].append(cve_id)
    
    return commit_to_cves


def main():
    """
    Main function to orchestrate the entire extraction process.
    """
    print("=" * 80)
    print("CVE Patch Extractor - Full File & Function Level Version")
    print("=" * 80)
    
    # Step 1: Load CSV data
    try:
        df = fetch_csv_data_from_local(CSV_FILENAME)
    except Exception as e:
        print(f"Error loading CSV: {e}")
        return
    
    patched_df = df.copy()
    print(f"\nProcessing all {len(patched_df)} vulnerabilities.")
    
    print("\nGrouping CVEs by commit hash...")
    commit_to_cves = group_cves_by_commit(patched_df)
    print(f"Found {len(commit_to_cves)} unique commits to process")
    
    # Step 2: Set up Git repository
    try:
        repo = setup_git_repository(REPO_CACHE_DIR, GLIBC_REPO_URL)
    except Exception as e:
        print(f"Error setting up repository: {e}")
        import traceback
        traceback.print_exc()
        return
    
    all_file_results = []
    total_commits = len(commit_to_cves)
    
    # Step 3: Extract FULL file content for all commits (Primary Dataset Generation)
    for idx, (commit_hash, cve_list) in enumerate(commit_to_cves.items(), 1):
        print(f"\n{'='*80}")
        print(f"Processing commit {idx}/{total_commits}: {commit_hash}")
        print(f"Associated CVEs: {', '.join(cve_list)}")
        print(f"{'='*80}")
        
        # Extract all .c files from this commit
        v_commit, file_results = extract_all_c_files_from_commit(repo, commit_hash)
        
        if not file_results or not v_commit:
            print(f"No .c files or parent commit found for P_COMMIT {commit_hash}")
            continue
        
        for cve_id in cve_list:
            for file_result in file_results:
                result = {
                    'CVE': cve_id,
                    'V_COMMIT': v_commit,
                    'P_COMMIT': commit_hash,
                    'FilePath': file_result['file_path'],
                    'V_CODE': file_result['vulnerable_code'],
                    'P_CODE': file_result['patched_code']
                }
                all_file_results.append(result)
        
        print(f"Created {len(file_results) * len(cve_list)} output rows (V_COMMIT={v_commit[:7]})")
        print(f"Total rows in full file dataset so far: {len(all_file_results)}")
    
    # Step 4: Save FULL File Results
    full_df = pd.DataFrame()
    if all_file_results:
        print(f"\n{'='*80}")
        print(f"Saving {len(all_file_results)} rows to FULL FILE DATASET: {FULL_FILE_OUTPUT_FILE}")
        print(f"{'='*80}")
        
        full_df = pd.DataFrame(all_file_results)
        # Use quoting=csv.QUOTE_ALL for multiline code strings
        full_df.to_csv(FULL_FILE_OUTPUT_FILE, index=False, quoting=csv.QUOTE_ALL)
        
        print(f"Full file dataset saved successfully!")
    else:
        print("\nNo full file results to save. Cannot proceed to function analysis.")
        return
    
    # Step 5: Generate Function-Level Dataset
    function_df = get_function_level_changes(full_df)
    
    # Step 6: Save Function-Level Results
    if not function_df.empty:
        print(f"\n{'='*80}")
        print(f"Saving {len(function_df)} rows to FUNCTION LEVEL DATASET: {FUNCTION_OUTPUT_FILE}")
        print(f"{'='*80}")
        
        function_df.to_csv(FUNCTION_OUTPUT_FILE, index=False, quoting=csv.QUOTE_ALL)
        print(f"Function-level dataset saved successfully!")
        
        # Show sample of function-level results
        print(f"\nSample of function-level data:")
        print(function_df[['CVE', 'V_COMMIT', 'F_NAME']].head(10))
        
        # Show statistics about function code sizes
        function_df['V_FUNC_lines'] = function_df['V_FUNCTION'].apply(lambda x: len(x.splitlines()) if x else 0)
        function_df['P_FUNC_lines'] = function_df['P_FUNCTION'].apply(lambda x: len(x.splitlines()) if x else 0)
        print(f"\nFunction code size statistics:")
        print(f"  - Total unique modified functions: {function_df['F_NAME'].nunique()}")
        print(f"  - Average vulnerable function lines: {function_df['V_FUNC_lines'].mean():.1f}")
        print(f"  - Average patched function lines: {function_df['P_FUNC_lines'].mean():.1f}")
    else:
        print("\nNo function-level changes found to save.")
    
    print("\n" + "=" * 80)
    print("Extraction and analysis complete!")
    print("=" * 80)


if __name__ == "__main__":
    main()
