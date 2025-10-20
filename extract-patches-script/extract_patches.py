import pandas as pd
import git
import os
import csv
import re
import difflib
from typing import Optional, Dict, List, Tuple, TextIO

# Configuration
CSV_FILENAME = "dump-glibc.csv"
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
FULL_FILE_OUTPUT_FILE = os.path.join(SCRIPT_DIR, "file_dataset.csv")
FUNCTION_OUTPUT_FILE = os.path.join(SCRIPT_DIR, "function_dataset.csv")
LOG_OUTPUT_FILE = os.path.join(SCRIPT_DIR, "script.log")

GLIBC_REPO_URL = "https://github.com/bminor/glibc.git"
REPO_CACHE_DIR = os.path.join(SCRIPT_DIR, "glibc_repo")

# --- Custom Logging Setup ---

# Global variable for the log file
log_file: Optional[TextIO] = None

# Store a reference to the built-in print function before it's potentially overwritten
# This MUST be done outside of the function that gets aliased to print
_original_print = __builtins__.print  # <--- FIX: Store the original print

def custom_log(*args, **kwargs):
    """Prints to console and writes to the log file."""
    message = " ".join(map(str, args))
    
    # 1. Print to console using the stored original function
    _original_print(message, **kwargs) # <--- FIX: Use the original print
    
    # 2. Write to log file
    if log_file:
        log_file.write(message + '\n')
        log_file.flush() # Ensure it's written immediately

# Replace the standard print with the custom logger
# This is where all subsequent 'print' calls will redirect
print = custom_log 

# --- End Custom Logging Setup ---


def strip_code_for_comparison(code: str) -> str:
    """
    Strips C-style comments and normalizes whitespace for comparison purposes.
    This is used to identify units where only comments or indentation changed.
    """
    if not code:
        return ""
    
    # 1. Remove C-style multi-line comments /* ... */
    code = re.sub(r'/\*.*?\*/', '', code, flags=re.DOTALL)
    
    # 2. Remove C++ style single-line comments // ...
    code = re.sub(r'//.*', '', code)
    
    # 3. Collapse all remaining whitespace (spaces, newlines, tabs) into a single space
    code = re.sub(r'\s+', ' ', code)
    
    return code.strip()


def extract_c_functions(code: str) -> Dict[str, str]:
    """
    Extracts C function definitions (name and body) from a source code string.
    ... [Function body remains the same as provided] ...
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
    Extracts multi-line C macro definitions, specifically those that might contain
    significant code changes (like function-like macros or multi-line bodies).
    
    REVISED Pattern: Focuses on matching a #define line followed by zero or more 
    lines that are continued using a backslash (\) character.
    """
    macros = {}
    
    # Pattern:
    # 1. ^\s*#define\s+([\w]+(?:\([\w,]*\))?)\s* -> Match #define and capture the name/params (Group 1)
    # 2. (?:[^\n]*\\\n)+?                       -> Non-greedy match for 1+ lines ending in a backslash
    # 3. [^\n]*$                                -> Match the final line that does NOT end with a backslash
    MACRO_BLOCK_PATTERN = re.compile(
        # Group 1: Macro Name (and optional parameters, e.g., MACRO(a, b))
        r'^\s*#define\s+([\w]+(?:[\w,()]*))' 
        # Group 2: The entire macro content block
        r'(\s*(?:[^\n]*\\\n)*[^\n]*)\s*',
        re.MULTILINE
    )

    for match in MACRO_BLOCK_PATTERN.finditer(code):
        # The full name (potentially with params)
        m_name_raw = match.group(1).strip()
        # Clean up name by removing parameters if present
        m_name = m_name_raw.split('(')[0].strip() 
        
        # Determine the full starting line index (to capture #define)
        define_line_start = code.rfind('\n', 0, match.start()) + 1
        
        # The content ends at the end of the match
        macro_code = code[define_line_start:match.end()].strip()
        
        # Simple heuristic check: only include macros that span multiple lines or 
        # contain complex structure (e.g., braces, semicolons)
        if '\n' in macro_code or re.search(r'[{;]', strip_code_for_comparison(macro_code)):
            if m_name not in macros:
                macros[m_name] = macro_code
                print(f"  [Macro Extracted] {m_name}")
        else:
             # Filters out simple #define PREPARE_LOOP \ int save_curcs; ...
             # These are single logical lines, but multi-line in text. We still
             # need to be careful. The previous simple filter was too harsh.
             # Let's trust the regex more and filter less aggressively here.
             
             # Reverting to basic logic: if it's found, include it, but ensure we 
             # are not capturing simple single-word definitions.
             
             # Final check: A macro that contains code (braces) or is explicitly multi-line is kept.
             if '\n' in macro_code or re.search(r'[{;]', strip_code_for_comparison(macro_code)):
                 if m_name not in macros:
                    macros[m_name] = macro_code
                    print(f"  [Macro Extracted] {m_name}")
             else:
                 print(f"  [Macro Skipped - Simple Definition] {m_name}")


    print(f"Total multi-line/complex macros extracted: {len(macros)}")
    return macros


def generate_changes_diff(v_code: str, p_code: str) -> str:
    """
    Generates a unified diff string between the vulnerable and patched code unit.
    """
    v_lines = v_code.splitlines(keepends=True)
    p_lines = p_code.splitlines(keepends=True)
    
    diff = difflib.unified_diff(
        v_lines, 
        p_lines, 
        fromfile='vulnerable', 
        tofile='patched', 
        lineterm=''
    )
    
    return "".join(diff)

def get_function_level_changes(full_df: pd.DataFrame) -> pd.DataFrame:
    """
    Analyzes the full file dataset to extract and compare individual C functions
    AND multi-line C macros that have been modified, generating the function-level dataset.
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
        
        # Ensure code exists for comparison (handle additions/deletions)
        if not v_full_code and not p_full_code:
            continue
        
        print(f"-> Analyzing {file_path} for CVE {cve_id}...")
        
        # 1. Extract Functions
        v_funcs = extract_c_functions(v_full_code)
        p_funcs = extract_c_functions(p_full_code)
        print(f"  Vulnerable Functions: {len(v_funcs)}, Patched Functions: {len(p_funcs)}")
        
        # 2. Extract Macros
        v_macros = extract_c_macros(v_full_code)
        p_macros = extract_c_macros(p_full_code)
        print(f"  Vulnerable Macros: {len(v_macros)}, Patched Macros: {len(p_macros)}")

        # 3. Combine Functions and Macros into one dictionary for comparison
        v_units = {**v_funcs, **v_macros}
        p_units = {**p_funcs, **p_macros}
        
        # Combine all unique unit names found in both versions
        all_unit_names = set(v_units.keys()) | set(p_units.keys())
        
        for unit_name in sorted(list(all_unit_names)):
            unit_type = "MACRO" if unit_name in v_macros or unit_name in p_macros else "FUNCTION"
            
            v_unit_code = v_units.get(unit_name, "")
            p_unit_code = p_units.get(unit_name, "")
            
            # 4. Compare stripped code to filter out comment/whitespace-only changes
            v_unit_code_stripped = strip_code_for_comparison(v_unit_code)
            p_unit_code_stripped = strip_code_for_comparison(p_unit_code)
            
            if v_unit_code_stripped != p_unit_code_stripped:
                # Code unit was modified by logical content
                
                print(f"  *** Found modified unit: {unit_name} ({unit_type}) ***")
                
                # 5. Generate the diff string using the ORIGINAL code (to keep full context)
                changes_diff = generate_changes_diff(v_unit_code, p_unit_code)
                
                # 6. Append to results
                function_results.append({
                    'CVE': cve_id,
                    'V_COMMIT': v_commit,
                    'P_COMMIT': p_commit,
                    'FilePath': file_path,
                    'F_NAME': unit_name,
                    'UNIT_TYPE': unit_type, # Added for clarity
                    'V_FUNCTION': v_unit_code,
                    'P_FUNCTION': p_unit_code,
                    'CHANGES': changes_diff
                })

    print(f"Function/Macro-level analysis complete. Found {len(function_results)} modified code units (excluding comment/whitespace-only changes).")
    if not function_results:
        return pd.DataFrame()
        
    results_df = pd.DataFrame(function_results)
    
    return results_df[['CVE', 'V_COMMIT', 'P_COMMIT', 'FilePath', 'F_NAME', 'UNIT_TYPE', 'V_FUNCTION', 'P_FUNCTION', 'CHANGES']]


def fetch_csv_data_from_local(filename: str) -> pd.DataFrame:
    """Read and parse a CSV file located in the same directory as this script."""
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
    """Clone or open the glibc git repository."""
    if os.path.exists(repo_path):
        print(f"Opening existing repository at {repo_path}")
        repo = git.Repo(repo_path)
        
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
    """Get the full content of a file at a specific commit."""
    try:
        commit = repo.commit(commit_hash)
        file_content = (commit.tree / file_path).data_stream.read()
        return file_content.decode('utf-8', errors='ignore')
    except (KeyError, AttributeError):
        return None
    except Exception as e:
        print(f"Error reading file {file_path} at commit {commit_hash}: {e}")
        return None


def extract_all_c_files_from_commit(repo: git.Repo, commit_hash: str) -> Tuple[Optional[str], List[Dict]]:
    """Extract FULL vulnerable and patched code from ALL .c files in a git commit."""
    print(f"Processing commit hash: {commit_hash}")
    
    v_commit_hash: Optional[str] = None
    
    try:
        commit = repo.commit(commit_hash)
        
        if not commit.parents:
            print(f"Commit {commit_hash} has no parents (initial commit), skipping...")
            return None, []
        
        parent_commit = commit.parents[0]
        v_commit_hash = parent_commit.hexsha
        print(f"Parent commit (V_COMMIT): {v_commit_hash}")
        
        diffs = parent_commit.diff(commit)
        
        print(f"Found {len(diffs)} file(s) changed in commit")
        
        results = []
        c_files_found = 0
        
        for diff_item in diffs:
            file_path = diff_item.b_path or diff_item.a_path
            
            if not file_path or not file_path.endswith('.c'):
                continue
            
            c_files_found += 1
            
            vulnerable_code = get_full_file_content(repo, v_commit_hash, file_path)
            patched_code = get_full_file_content(repo, commit.hexsha, file_path)
            
            # ... [Code for handling additions/deletions/skipping remains the same] ...
            
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
        print(traceback.format_exc())
        return None, []


def group_cves_by_commit(df: pd.DataFrame) -> Dict[str, List[str]]:
    """Group CVE IDs by their P_COMMIT hash to avoid processing the same commit multiple times."""
    # ... [Function body remains the same as provided] ...
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
        
        if cve_id not in commit_to_cves[commit_hash]:
            commit_to_cves[commit_hash].append(cve_id)
    
    return commit_to_cves


def main():
    """Main function to orchestrate the entire extraction process."""
    global log_file
    
    # Step 0: Initialize Logging
    try:
        log_file = open(LOG_OUTPUT_FILE, 'w')
        print(f"Logging output to {LOG_OUTPUT_FILE}")
    except Exception as e:
        print(f"FATAL: Could not open log file {LOG_OUTPUT_FILE}: {e}")
        return
        
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
        print(traceback.format_exc())
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
        full_df.to_csv(FULL_FILE_OUTPUT_FILE, index=False, quoting=csv.QUOTE_ALL)
        
        print(f"Full file dataset saved successfully!")
    else:
        print("\nNo full file results to save. Cannot proceed to function analysis.")
        log_file.close()
        return
    
    # Step 5: Generate Function-Level Dataset
    function_df = get_function_level_changes(full_df)
    
    # Step 6: Save Function-Level Results
    if not function_df.empty:
        print(f"\n{'='*80}")
        print(f"Saving {len(function_df)} rows to FUNCTION LEVEL DATASET: {FUNCTION_OUTPUT_FILE}")
        print(f"{'='*80}")
        
        # Ensure the new UNIT_TYPE column is included
        function_df.to_csv(FUNCTION_OUTPUT_FILE, index=False, quoting=csv.QUOTE_ALL)
        print(f"Function-level dataset saved successfully!")
        
        # Show sample of function-level results
        print(f"\nSample of function-level data:")
        print(function_df[['CVE', 'V_COMMIT', 'F_NAME', 'UNIT_TYPE']].head(10))
        
        # Show statistics about function code sizes
        function_df['V_FUNC_lines'] = function_df['V_FUNCTION'].apply(lambda x: len(x.splitlines()) if x else 0)
        function_df['P_FUNC_lines'] = function_df['P_FUNCTION'].apply(lambda x: len(x.splitlines()) if x else 0)
        print(f"\nFunction code size statistics:")
        print(f"  - Total unique modified units (Funcs/Macros): {len(function_df)}")
        print(f"  - Modified Functions: {len(function_df[function_df['UNIT_TYPE'] == 'FUNCTION'])}")
        print(f"  - Modified MACROS: {len(function_df[function_df['UNIT_TYPE'] == 'MACRO'])}")
        print(f"  - Average vulnerable unit lines: {function_df['V_FUNC_lines'].mean():.1f}")
        print(f"  - Average patched unit lines: {function_df['P_FUNC_lines'].mean():.1f}")
    else:
        print("\nNo function-level changes found to save.")
    
    print("\n" + "=" * 80)
    print("Extraction and analysis complete!")
    print("=" * 80)
    
    # Final cleanup
    if log_file:
        log_file.close()

if __name__ == "__main__":
    main()