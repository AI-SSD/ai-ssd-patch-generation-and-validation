# Save as: analyze_vulns_and_benchmark.py
import pandas as pd
import ollama
import sys
import os
import csv
import re
import time
from collections import defaultdict, Counter

# --- Configuration ---
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
# Input CSV file
CSV_FILE_PATH = os.path.join(SCRIPT_DIR, 'file-function.csv')
# Input Exploits Directory
EXPLOITS_DIR = os.path.join(SCRIPT_DIR, 'exploits')

# --- Models to Benchmark ---
MODEL_NAMES = [
    'qwen2.5-coder:1.5b',
    'qwen2.5-coder:7b',
    'qwen2.5:1.5b',
    'qwen2.5:7b'
]

# --- Outputs ---
# 1. Directory for individual .md files (will have subfolders per model)
OUTPUT_MD_DIR = os.path.join(SCRIPT_DIR, 'vulnerable_analysis_benchmark')
# 2. Consolidated CSV file (inside the same directory)
OUTPUT_CSV_PATH = os.path.join(OUTPUT_MD_DIR, 'glibc_vulns_benchmarked.csv')
# 3. Directory for patched .c files (will have subfolders per model)
OUTPUT_PATCH_DIR = os.path.join(SCRIPT_DIR, 'patched_code_benchmark')
# 4. Directory for FULL patched files (original file + patch injected)
OUTPUT_FULL_PATCH_DIR = os.path.join(SCRIPT_DIR, 'full_patched_files_benchmark')
# 5. Text file to store the final analytics logs
OUTPUT_STATS_FILE = os.path.join(OUTPUT_MD_DIR, 'benchmark_summary.txt')

# ---------------------

def separate_functions(code_block, f_name):
    """
    Tries to separate a code block into a main patched function
    and a list of helper functions.
    """
    function_starts_regex = r'\n\s*(?=(?:static|inline|__inline__|void|int|char|long|double|float|struct|enum|unsigned|const)[\s\*]+[\w\:]+\s*\([^)]*\)\s*\{)'
    
    try:
        potential_functions = re.split(function_starts_regex, code_block.strip())
        functions = [f.strip() for f in potential_functions if f.strip()]
        
        if not functions:
            return code_block, []

        main_patched_func = None
        helper_funcs = []
        
        f_name_regex = rf'\b{re.escape(f_name)}\b'
        
        for func in functions:
            signature = func.split('{', 1)[0]
            if re.search(f_name_regex, signature):
                main_patched_func = func
            else:
                helper_funcs.append(func)
        
        if main_patched_func is None and functions:
            main_patched_func = functions[-1]
            helper_funcs = functions[:-1]
        elif main_patched_func is None and not functions:
            main_patched_func = code_block
            
        return main_patched_func, helper_funcs

    except Exception as e:
        print(f"  [!] Warning: Function parsing failed: {e}")
        return code_block, []

def analyze_code(client, model_name, index, cve, vulnerable_code, full_file_content, poc_code):
    """
    Analyzes a vulnerable function using Ollama.
    """
    print(f"\n--- Analyzing CVE: {cve} (Row: {index}) with Model: {model_name} ---")
    results = {}
    start_time = time.time()

    file_context_prompt = ""
    if full_file_content and not pd.isna(full_file_content) and full_file_content.strip():
        file_context_prompt = f"""
    For additional context, this function is from the following full file:
    ```c
    {full_file_content}
    ```
    """

    poc_context_prompt = ""
    if poc_code and not pd.isna(poc_code) and poc_code.strip():
        poc_context_prompt = f"""
    To help understand the attack vector, here is a Proof of Concept (PoC) that exploits this vulnerability:
    ```c
    {poc_code}
    ```
    """

    try:
        # --- Prompt 1: Analyze ---
        prompt1 = f"""
        {file_context_prompt}

        Here is the specific vulnerable C function from glibc (CVE: {cve}) that you must analyze:
        ```c
        {vulnerable_code}
        ```
        
        {poc_context_prompt}

        Analyze *this specific function* and identify the security vulnerability.
        Explain the type of vulnerability (e.g., buffer overflow, integer overflow, use-after-free).
        Do NOT generate a new Proof of Concept (PoC).
        """
        response1 = client.chat(
            model=model_name,
            messages=[{'role': 'user', 'content': prompt1}]
        )
        vuln_analysis = response1['message']['content']
        results['vulnerability_analysis'] = vuln_analysis
        print(f"\n[Vulnerability Analysis]: Complete.")

        # --- Prompt 2: Patch ---
        prompt2 = f"""
        You just analyzed the following vulnerable code for {cve}:
        ```c
        {vulnerable_code}
        ```
        {file_context_prompt}
        {poc_context_prompt}

        Based on your analysis, please generate the patched C code to fix the vulnerability.
        
        **Your output MUST adhere to these rules:**
        1.  You **must** provide the complete, patched version of the original function (`{vulnerable_code}`).
        2.  If the fix requires creating a **new helper function**, you **must** include that new helper function in your response.
        3.  Your entire output **must** be a single C code block, enclosed in one pair of markdown backticks (```c ... ```). Place any new helper functions *before* the patched original function.
        
        Only output the code.
        """
        response2 = client.chat(
            model=model_name,
            messages=[{'role': 'user', 'content': prompt2}]
        )
        patched_code_raw = response2['message']['content']
        results['patched_code_raw'] = patched_code_raw
        print(f"[Suggested Patch]: Complete.")

        # --- Prompt 3: Explain ---
        prompt3 = f"""
        You just generated the following patch for {cve}:
        {patched_code_raw}

        Explain the changes you made (the "diff") and why they effectively mitigate the vulnerability.
        Format this explanation like a git commit message or diff notes.
        """
        response3 = client.chat(
            model=model_name,
            messages=[{'role': 'user', 'content': prompt3}]
        )
        patch_explanation = response3['message']['content']
        results['patch_explanation'] = patch_explanation
        print(f"[Patch Explanation]: Complete.")
        
        end_time = time.time()
        results['runtime_s'] = end_time - start_time
        
        return results

    except Exception as e:
        end_time = time.time()
        print(f"Error analyzing {cve} with {model_name}: {e}")
        return {
            "vulnerability_analysis": f"Error: {e}",
            "patched_code_raw": f"Error: {e}",
            "patch_explanation": f"Error: {e}",
            "runtime_s": end_time - start_time
        }

def extract_vuln_type(analysis_text):
    """Extracts vulnerability type from analysis text."""
    if not analysis_text or "Error:" in analysis_text:
        return "Extraction Failed/Error"
        
    patterns = {
        r'buffer\s+overflo': 'Buffer Overflow',
        r'integer\s+overflo': 'Integer Overflow/Underflow',
        r'use-after-free': 'Use-After-Free',
        r'memory\s+corruption': 'Memory Corruption',
        r'race\s+condition': 'Race Condition',
        r'broken\s+access\s+control': 'Access Control Issue',
        r'injection': 'Injection Flaw',
        r'null\s+pointer': 'Null Pointer Dereference'
    }
    
    for pattern, vuln_type in patterns.items():
        if re.search(pattern, analysis_text, re.IGNORECASE):
            return vuln_type
            
    if len(analysis_text) > 50:
        return "Generic Flaw Described"
        
    return "Not Detected"

def save_patched_code(model_name, cve, row_index, patched_code_content, f_name):
    """Saves the extracted patched C code (snippet only)."""
    model_patch_dir = os.path.join(OUTPUT_PATCH_DIR, model_name.replace(':', '_'))
    if not os.path.exists(model_patch_dir):
        os.makedirs(model_patch_dir)
        
    safe_cve_name = str(cve).replace('/', '_').replace('\\', '_')
    safe_f_name = str(f_name).replace('/', '_').replace('\\', '_')
    output_c_filename = os.path.join(model_patch_dir, f"{safe_cve_name}_{safe_f_name}_Row-{row_index}_patched.c")
    
    if "Error:" in patched_code_content:
         return
         
    try:
        with open(output_c_filename, 'w', encoding='utf-8') as f:
            f.write(patched_code_content)
    except Exception as e:
        print(f"  [!] Error saving .c file {output_c_filename}: {e}")

def save_aggregated_file(model_name, cve, original_file_path, original_content, patches):
    """
    Saves the FULL original file with ALL vulnerable functions replaced by their patched versions.
    Aggregates multiple patches for the same file.
    """
    if not original_content or pd.isna(original_content):
        return

    # Directory Structure: OUTPUT_FULL_PATCH_DIR / CVE_ID / MODEL_NAME
    safe_cve = str(cve).replace('/', '_').replace('\\', '_')
    safe_model = model_name.replace(':', '_')
    
    target_dir = os.path.join(OUTPUT_FULL_PATCH_DIR, safe_cve, safe_model)
    if not os.path.exists(target_dir):
        os.makedirs(target_dir)

    # Prepare content
    new_full_content = original_content
    
    # Apply all patches for this file
    for v_function, patched_code in patches:
        if "Error:" in patched_code:
            continue
            
        # Try exact replacement
        if v_function in new_full_content:
            new_full_content = new_full_content.replace(v_function, patched_code)
        # Try stripped replacement
        elif v_function.strip() in new_full_content:
            new_full_content = new_full_content.replace(v_function.strip(), patched_code)
        else:
            print(f"  [!] Warning: Could not locate function in {original_file_path} for CVE {cve}")
            # Append fallback
            new_full_content += f"\n\n/* AUTOMATED NOTE: REPLACEMENT FAILED - PATCH APPENDED BELOW */\n{patched_code}"

# Filename: actual_filename.c
    # Use os.path.basename(original_file_path)
    base_name = os.path.basename(str(original_file_path))
    if not base_name or base_name == 'nan':
        base_name = "unknown_file.c"
    
    # Prepend underscore to match docker-envs/patches structure
    if not base_name.startswith('_'):
        base_name = "_" + base_name
        
    output_path = os.path.join(target_dir, base_name)

    try:
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(new_full_content)
        print(f"  [+] Full patched file saved: {output_path}")
    except Exception as e:
        print(f"  [!] Error saving full file {output_path}: {e}")

def generate_benchmark_stats(benchmark_df, original_df_len):
    """Generates statistics, prints them, and saves them to a text file."""
    
    # We will accumulate the output in this list to write to file later
    log_buffer = []

    def log(msg=""):
        """Helper to print to console AND append to buffer"""
        print(msg)
        log_buffer.append(str(msg))

    log("\n" + "="*80)
    log("LLM VULNERABILITY ANALYSIS BENCHMARK RESULTS")
    log("="*80)
    log(f"Total CVEs analyzed: {original_df_len}")
    log(f"Total analysis rows generated: {len(benchmark_df)}")
    
    log("\n### 1. Performance Overview")
    def is_error(s):
        return pd.isna(s) or "Error:" in str(s) or "Skipped" in str(s)

    stats = []
    for model_name in MODEL_NAMES:
        model_data = benchmark_df[benchmark_df['MODEL_NAME'] == model_name]
        total_attempts = len(model_data)
        successes = model_data['P_FUNCTION'].apply(lambda x: not is_error(x)).sum()
        errors = total_attempts - successes
        avg_runtime = model_data['RUNTIME_S'].mean()
        
        stats.append({
            'Model': model_name,
            'Successes': successes,
            'Errors': errors,
            'Success Rate': f"{successes / total_attempts * 100:.2f}%" if total_attempts else "N/A",
            'Avg Runtime (s)': f"{avg_runtime:.2f}" if total_attempts > 0 else "N/A"
        })
    
    # Create DataFrame and log the markdown table
    stats_df = pd.DataFrame(stats).set_index('Model')
    log(stats_df.to_markdown())

    log("\n### 2. Vulnerability Type Distribution")
    type_counts = defaultdict(Counter)
    for index, row in benchmark_df.iterrows():
        type_counts[row['MODEL_NAME']][row['VULN_TYPE']] += 1
        
    type_df = pd.DataFrame.from_dict(type_counts, orient='index').fillna(0).astype(int)
    log(type_df.to_markdown())
    
    log("\n" + "="*80)
    log(f"Patched Snippets: {OUTPUT_PATCH_DIR}")
    log(f"Full Patched Files: {OUTPUT_FULL_PATCH_DIR}")
    log(f"Full Analytics Log: {OUTPUT_STATS_FILE}")
    log("="*80)

    # Write the buffer to the file
    try:
        with open(OUTPUT_STATS_FILE, 'w', encoding='utf-8') as f:
            f.write('\n'.join(log_buffer))
        print(f"\n[+] Analytics successfully saved to: {OUTPUT_STATS_FILE}")
    except Exception as e:
        print(f"\n[!] Error saving analytics file: {e}")

def main():
    try:
        csv.field_size_limit(sys.maxsize)
    except OverflowError:
        csv.field_size_limit(int(2**31 - 1))

    # Create output directories
    for d in [OUTPUT_MD_DIR, OUTPUT_PATCH_DIR, OUTPUT_FULL_PATCH_DIR]:
        if not os.path.exists(d):
            os.makedirs(d)
            print(f"Created directory: {d}")

    if not os.path.isdir(EXPLOITS_DIR):
        print(f"Warning: Exploit directory '{EXPLOITS_DIR}' not found.")
        
    try:
        df = pd.read_csv(CSV_FILE_PATH, sep=';', engine='python')
        print(f"Loaded CSV with {len(df)} rows.")
    except Exception as e:
        print(f"Error reading CSV: {e}")
        sys.exit(1)

    # Pre-calculate CVE frequencies to determine if versioning is needed
    cve_counts_total = df['CVE'].value_counts().to_dict()

    has_v_file = 'V_FILE' in df.columns
    
    try:
        client = ollama.Client()
        client.list()
    except Exception as e:
        print(f"Error connecting to Ollama: {e}")
        sys.exit(1)

    csv_results_list = []

    for model_name in MODEL_NAMES:
        print("\n" + "#"*80)
        print(f"  STARTING BENCHMARK FOR MODEL: {model_name}")
        print("#"*80)
        
        # Dictionary to aggregate patches per file
        # Key: (CVE, FilePath) -> Value: {'content': V_FILE, 'patches': [(v_func, patched_code)]}
        model_file_aggregations = {} 
        
        # Track current version for each CVE within this model's run
        current_cve_versions = defaultdict(int)

        for index, row in df.iterrows():
            original_cve = row.get('CVE', f'Row_{index}')
            
            # Determine Output CVE Name (Versioning)
            current_cve_versions[original_cve] += 1
            if cve_counts_total.get(original_cve, 0) > 1:
                cve_folder_name = f"{original_cve} v{current_cve_versions[original_cve]}"
            else:
                cve_folder_name = original_cve
            
            cve = original_cve

            v_function = row.get('V_FUNCTION')
            f_name = row.get('F_NAME', 'unknown_func')
            v_file = row.get('V_FILE') if has_v_file else None
            file_path_col = str(row.get('FilePath', 'unknown.c')).strip()

            # Load PoC
            poc_code = None
            cve_str = str(original_cve)
            for filename in [cve_str, f"{cve_str}.c", f"{cve_str}.txt"]:
                poc_path = os.path.join(EXPLOITS_DIR, filename)
                if os.path.exists(poc_path):
                    try:
                        with open(poc_path, 'r', encoding='utf-8', errors='ignore') as f:
                            poc_code = f.read()
                        break
                    except: pass

            if pd.isna(v_function) or not v_function.strip():
                continue
                
            # 1. Analyze
            llm_results = analyze_code(client, model_name, index, original_cve, v_function, v_file, poc_code)
            
            # 2. Extract Patch
            patched_code_raw = llm_results.get('patched_code_raw', 'Error')
            
            # Try to extract code block using regex
            code_block_match = re.search(r'```c\s*(.*?)\s*```', patched_code_raw, re.DOTALL | re.IGNORECASE)
            if code_block_match:
                patched_code_clean = code_block_match.group(1).strip()
            else:
                # Fallback: try to find any code block
                code_block_match = re.search(r'```\s*(.*?)\s*```', patched_code_raw, re.DOTALL)
                if code_block_match:
                    patched_code_clean = code_block_match.group(1).strip()
                else:
                    # Fallback: just strip (risky but better than nothing if no blocks)
                    patched_code_clean = patched_code_raw.strip().replace('```c', '').replace('```', '').strip()

            # 3. Save Isolated Snippet (Keep existing logic for snippets)
            save_patched_code(model_name, cve, index, patched_code_clean, f_name)

            # 4. Aggregate for Full Patched File
            # We store the patch to be applied later
            file_key = (cve_folder_name, file_path_col)
            if file_key not in model_file_aggregations:
                model_file_aggregations[file_key] = {
                    'content': v_file,
                    'patches': []
                }
            model_file_aggregations[file_key]['patches'].append((v_function, patched_code_clean))
            
            # 5. Save MD Analysis
            model_md_dir = os.path.join(OUTPUT_MD_DIR, model_name.replace(':', '_'))
            if not os.path.exists(model_md_dir): os.makedirs(model_md_dir)
            safe_cve = str(cve).replace('/', '_')
            
            md_content = f"Model: {model_name}\nCVE: {cve}\n\n[Analysis]\n{llm_results.get('vulnerability_analysis')}\n\n[Patch]\n{patched_code_raw}\n\n[Explanation]\n{llm_results.get('patch_explanation')}"
            
            with open(os.path.join(model_md_dir, f"{safe_cve}_Row-{index}_analysis.md"), 'w', encoding='utf-8') as f:
                f.write(md_content)

            # 6. Prepare CSV Row
            main_func, helper_funcs = separate_functions(patched_code_clean, f_name)
            new_row = row.to_dict()
            new_row.update({
                'MODEL_NAME': model_name,
                'P_FUNCTION': main_func,
                'CHANGES': llm_results.get('patch_explanation'),
                'RUNTIME_S': llm_results.get('runtime_s'),
                'VULN_TYPE': extract_vuln_type(llm_results.get('vulnerability_analysis'))
            })
            if helper_funcs:
                for i, h in enumerate(helper_funcs):
                    new_row[f'FUNCTION_{i+1}'] = h
            
            csv_results_list.append(new_row)

        # After iterating all rows for this model, save the aggregated files
        print(f"\n--- Generating Aggregated Full Files for {model_name} ---")
        for (cve, f_path), data in model_file_aggregations.items():
            save_aggregated_file(model_name, cve, f_path, data['content'], data['patches'])

    # Final CSV Save & Stats
    if csv_results_list:
        output_df = pd.DataFrame(csv_results_list)
        original_cols = df.columns.tolist()
        new_static = ['MODEL_NAME', 'VULN_TYPE', 'RUNTIME_S', 'P_FUNCTION', 'CHANGES']
        helpers = sorted([c for c in output_df.columns if c.startswith('FUNCTION_')], key=lambda x: int(x.split('_')[1]))
        output_df = output_df.reindex(columns=original_cols + new_static + helpers)
        output_df.to_csv(OUTPUT_CSV_PATH, sep=';', index=False, encoding='utf-8')
        
        generate_benchmark_stats(output_df, len(df))

if __name__ == "__main__":
    main()
