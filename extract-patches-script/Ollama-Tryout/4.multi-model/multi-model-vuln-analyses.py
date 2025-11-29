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

# ---------------------

def separate_functions(code_block, f_name):
    """
    Tries to separate a code block into a main patched function
    and a list of helper functions.
    
    Uses the function name `f_name` to identify the main function.
    Returns: (main_function_str, [helper_function_str_1, ...])
    """
    # Regex to split the code block by lines that look like
    # the start of a C function definition.
    function_starts_regex = r'\n\s*(?=(?:static|inline|__inline__|void|int|char|long|double|float|struct|enum|unsigned|const)[\s\*]+[\w\:]+\s*\([^)]*\)\s*\{)'
    
    try:
        # Split the code block into potential function strings
        potential_functions = re.split(function_starts_regex, code_block.strip())
        functions = [f.strip() for f in potential_functions if f.strip()]
        
        if not functions:
            return code_block, []

        main_patched_func = None
        helper_funcs = []
        
        # Try to identify main function by f_name
        f_name_regex = rf'\b{re.escape(f_name)}\b'
        
        for func in functions:
            signature = func.split('{', 1)[0]
            if re.search(f_name_regex, signature):
                main_patched_func = func
            else:
                helper_funcs.append(func)
        
        # Fallback
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
    Analyzes a vulnerable function using Ollama and returns the
    analysis, patched code, explanation, and runtime.
    
    Returns a dictionary:
    {
        "vulnerability_analysis": "...",
        "patched_code_raw": "...",
        "patch_explanation": "...",
        "runtime_s": float
    }
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
        # --- Prompt 1: Analyze the vulnerability ---
        prompt1 = f"""
        {file_context_prompt}

        Here is the specific vulnerable C function from glibc (CVE: {cve}) that you must analyze:
        ```c
        {vulnerable_code}
        ```
        
        {poc_context_prompt}

        Analyze *this specific function* and identify the security vulnerability.
        Explain the type of vulnerability (e.g., buffer overflow, integer overflow, use-after-free)
        and describe how it could be triggered, using the PoC for context if provided.
        Do NOT generate a new Proof of Concept (PoC).
        Your analysis must focus on the function provided above, using the full file and PoC for context only.
        """
        response1 = client.chat(
            model=model_name,
            messages=[{'role': 'user', 'content': prompt1}]
        )
        vuln_analysis = response1['message']['content']
        results['vulnerability_analysis'] = vuln_analysis
        print(f"\n[Vulnerability Analysis]: Complete.")

        # --- Prompt 2: Generate a patch ---
        prompt2 = f"""
        You just analyzed the following vulnerable code for {cve}:
        ```c
        {vulnerable_code}
        ```
        {file_context_prompt}
        {poc_context_prompt}

        Based on your analysis (and the provided PoC, if any), please generate the patched C code to fix the vulnerability.
        Your patch must be robust enough to prevent the exploit shown in the PoC.

        **Your output MUST adhere to these rules:**
        1.  You **must** provide the complete, patched version of the original function (`{vulnerable_code}`).
        2.  If the fix requires creating a **new helper function**, you **must** include that new helper function in your response.
        3.  Your entire output **must** be a single C code block, enclosed in one pair of markdown backticks (```c ... ```). Place any new helper functions *before* the patched original function.
        
        Only output the code. Do not add any explanation before or after the ````c` block.
        """
        response2 = client.chat(
            model=model_name,
            messages=[{'role': 'user', 'content': prompt2}]
        )
        patched_code_raw = response2['message']['content']
        results['patched_code_raw'] = patched_code_raw
        print(f"[Suggested Patch]: Complete.")

        # --- Prompt 3: Explain the patch ---
        prompt3 = f"""
        You just generated the following patch for {cve}:
        {patched_code_raw}

        This patch was for the following original vulnerable function:
        ```c
        {vulnerable_code}
        ```
        Explain the changes you made (the "diff") and why they
        effectively mitigate the vulnerability (especially considering the PoC you may have seen).

        - Be specific about the lines changed in the original function.
        - **If you added any new helper functions,** explain their purpose and why they were necessary for the fix.
        - Format this explanation like a git commit message or diff notes.
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
    """
    A simple function to try and extract a common vulnerability type
    from the analysis text for comparison.
    """
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
    
    # Prioritize specific types over generic ones (e.g., Buffer Overflow > Memory Corruption)
    for pattern, vuln_type in patterns.items():
        if re.search(pattern, analysis_text, re.IGNORECASE):
            return vuln_type
            
    # If no specific type found, check for a generic description of a flaw
    if len(analysis_text) > 50:
        return "Generic Flaw Described"
        
    return "Not Detected"

# NEW FUNCTION TO SAVE PATCHED CODE
def save_patched_code(model_name, cve, row_index, patched_code_content, f_name):
    """
    Saves the extracted patched C code to a model-specific .c file.
    The filename is based on the CVE and the original function name.
    """
    model_patch_dir = os.path.join(OUTPUT_PATCH_DIR, model_name.replace(':', '_'))
    if not os.path.exists(model_patch_dir):
        os.makedirs(model_patch_dir)
        
    safe_cve_name = str(cve).replace('/', '_').replace('\\', '_')
    safe_f_name = str(f_name).replace('/', '_').replace('\\', '_')
    # Use f_name for a more descriptive filename, fallback to CVE
    output_c_filename = os.path.join(model_patch_dir, f"{safe_cve_name}_{safe_f_name}_Row-{row_index}_patched.c")
    
    # Clean code: remove markdown backticks (already done in main, but as a safeguard)
    code_to_save = patched_code_content.strip().replace('```c', '').replace('```', '').strip()
    
    if "Error:" in code_to_save:
         print(f"  [!] Skipping .c file save for {cve} due to patch generation error.")
         return
         
    try:
        with open(output_c_filename, 'w', encoding='utf-8') as f:
            f.write(code_to_save)
        print(f"  [+] Patched .c file saved to: {output_c_filename}")
    except Exception as e:
        print(f"  [!] Error saving .c file {output_c_filename}: {e}")
        
# END NEW FUNCTION

def generate_benchmark_stats(benchmark_df, original_df_len):
    """
    Generates and prints the final statistics from the benchmark DataFrame.
    """
    print("\n" + "="*80)
    print("LLM VULNERABILITY ANALYSIS BENCHMARK RESULTS")
    print("="*80)
    print(f"Total CVEs analyzed: {original_df_len}")
    print(f"Total analysis rows generated: {len(benchmark_df)}")
    
    # 1. Overall Success/Error Rate & Average Runtime
    print("\n### 1. Performance Overview (Success Rate & Runtime)")
    
    # Count errors (where P_FUNCTION contains "Error" or "Skipped")
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
        
    stats_df = pd.DataFrame(stats).set_index('Model')
    print(stats_df.to_markdown())

    # 2. Vulnerability Type Consistency Check
    print("\n### 2. Vulnerability Type Consistency (CVE by CVE)")
    
    # Group by CVE to see if all models agree on the vulnerability type
    consistency_data = []
    for cve, group in benchmark_df.groupby('CVE'):
        vuln_types = group.set_index('MODEL_NAME')['VULN_TYPE'].to_dict()
        
        # Check if all non-Error/Not Detected types are the same
        valid_types = [v for v in vuln_types.values() if v not in ["Extraction Failed/Error", "Not Detected", "Generic Flaw Described", "Skipped"]]
        is_consistent = len(set(valid_types)) <= 1
        
        consistency_data.append({
            'CVE': cve,
            'Is Consistent': is_consistent,
            **vuln_types # Spread the model types (e.g., 'qwen2.5:1.5b': 'Buffer Overflow')
        })
        
    consistency_df = pd.DataFrame(consistency_data).set_index('CVE')
    
    # Print a summary of consistency
    consistent_count = consistency_df['Is Consistent'].sum()
    print(f"\nTotal CVEs: {original_df_len}")
    print(f"CVEs where all successful models agreed on type: {consistent_count}")
    print(f"Consistency Rate: {consistent_count / original_df_len * 100:.2f}%")
    
    # Print the full consistency table (optional: uncomment for full detail)
    # print("\nFull Consistency Table:")
    # print(consistency_df.to_markdown())
    
    # 3. Aggregated Vulnerability Type Distribution
    print("\n### 3. Aggregated Vulnerability Type Distribution")
    
    type_counts = defaultdict(Counter)
    for index, row in benchmark_df.iterrows():
        type_counts[row['MODEL_NAME']][row['VULN_TYPE']] += 1
        
    type_df = pd.DataFrame.from_dict(type_counts, orient='index').fillna(0).astype(int)
    
    # Normalize by the number of attempts for each model
    total_attempts_per_model = {model: benchmark_df[benchmark_df['MODEL_NAME'] == model_name].shape[0] for model in MODEL_NAMES}
    
    # Print raw counts
    print("\nRaw Counts of Detected Vulnerability Types:")
    print(type_df.to_markdown())
    
    # Print normalized percentages (optional)
    # print("\nNormalized Percentages:")
    # type_df_norm = type_df.apply(lambda x: (x / total_attempts_per_model[x.name]) * 100, axis=1).round(2)
    # print(type_df_norm.to_markdown())
    
    print("\n" + "="*80)
    print("Benchmark completed. Check glibc_vulns_benchmarked.csv for full data.")
    print(f"Patched C code is saved in the **{OUTPUT_PATCH_DIR}** directory.")
    print("="*80)

def main():
    # Increase CSV field limit
    try:
        csv.field_size_limit(sys.maxsize)
    except OverflowError:
        csv.field_size_limit(int(2**31 - 1))

    # Create output directories
    if not os.path.exists(OUTPUT_MD_DIR):
        os.makedirs(OUTPUT_MD_DIR)
        print(f"Created analysis output directory: {OUTPUT_MD_DIR}")
        
    if not os.path.exists(OUTPUT_PATCH_DIR):
        os.makedirs(OUTPUT_PATCH_DIR)
        print(f"Created patched code output directory: {OUTPUT_PATCH_DIR}")

    # Check for Exploit Dir
    if not os.path.isdir(EXPLOITS_DIR):
        print(f"Warning: Exploit directory '{EXPLOITS_DIR}' not found. Will proceed without PoC file context.")
    else:
        print(f"Using exploit directory: {EXPLOITS_DIR}")
        
    try:
        df = pd.read_csv(CSV_FILE_PATH, sep=';', engine='python')
        print(f"Successfully loaded '{CSV_FILE_PATH}'. {len(df)} rows found.")
    except FileNotFoundError:
        print(f"Error: The file '{CSV_FILE_PATH}' was not found.")
        sys.exit(1)
    except Exception as e:
        print(f"Error reading CSV: {e}")
        sys.exit(1)

    required_input_columns = ['CVE', 'V_COMMIT', 'FilePath', 'F_NAME', 'UNIT_TYPE', 'V_FUNCTION']
    missing_cols = [col for col in required_input_columns if col not in df.columns]
    if missing_cols:
        print(f"Error: Input CSV is missing required columns: {missing_cols}")
        sys.exit(1)
        
    has_v_file = 'V_FILE' in df.columns
    if has_v_file:
        print("Found optional 'V_FILE' column. It will be used for context.")
    else:
        print("Optional 'V_FILE' column not found. Proceeding without full file context.")
    
    try:
        client = ollama.Client()
        client.list()
        print(f"Successfully connected to Ollama.")
    except Exception as e:
        print("Error connecting to Ollama. Is the Ollama server running?")
        print(f"Details: {e}")
        sys.exit(1)

    # This list will store dictionaries for the new CSV (one row per CVE-Model pair)
    csv_results_list = []

    # Outer loop: Iterate over all models
    for model_name in MODEL_NAMES:
        print("\n" + "#"*80)
        print(f"  STARTING BENCHMARK FOR MODEL: {model_name}")
        print("#"*80)
        
        # Inner loop: Iterate over the original dataframe (CVEs)
        for index, row in df.iterrows():
            cve = row.get('CVE', f'Row_{index}')
            v_function = row.get('V_FUNCTION')
            f_name = row.get('F_NAME', 'unknown_func')
            v_file = row.get('V_FILE') if has_v_file else None

            # --- Load PoC code from file (same as original logic) ---
            poc_code = None
            cve_str = str(cve)
            potential_filenames = [cve_str, f"{cve_str}.c", f"{cve_str}.txt"]
            
            for filename in potential_filenames:
                poc_file_path = os.path.join(EXPLOITS_DIR, filename)
                if os.path.exists(poc_file_path):
                    try:
                        with open(poc_file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            poc_code = f.read()
                        print(f"  [+] Found and loaded PoC for {cve}: {filename}")
                        break
                    except Exception as e:
                        print(f"  [!] Failed to read PoC file {poc_file_path}: {e}")
                        break
            # --- END PoC LOGIC ---

            if pd.isna(v_function) or not v_function.strip():
                print(f"Skipping row {index} (CVE: {cve}) due to missing V_FUNCTION.")
                new_row = row.to_dict()
                new_row['MODEL_NAME'] = model_name
                new_row['P_FUNCTION'] = "Skipped - Missing V_FUNCTION"
                new_row['CHANGES'] = "Skipped - Missing V_FUNCTION"
                new_row['RUNTIME_S'] = 0.0
                new_row['VULN_TYPE'] = "Skipped"
                csv_results_list.append(new_row)
                continue
                
            # 1. Analyze the code
            llm_results = analyze_code(client, model_name, index, cve, v_function, v_file, poc_code)
            
            # 2. Extract and clean the patched code
            patched_code_raw = llm_results.get('patched_code_raw', 'Error')
            patched_code_clean = patched_code_raw.strip().replace('```c', '').replace('```', '').strip()

            # 3. Save the patched C code
            save_patched_code(model_name, cve, index, patched_code_clean, f_name)
            
            # 4. Save the individual .md file (in a model-specific subfolder)
            model_md_dir = os.path.join(OUTPUT_MD_DIR, model_name.replace(':', '_'))
            if not os.path.exists(model_md_dir):
                os.makedirs(model_md_dir)
            
            safe_cve_name = str(cve).replace('/', '_').replace('\\', '_')
            output_md_filename = os.path.join(model_md_dir, f"{safe_cve_name}_Row-{index}_analysis.md")
            
            analysis_content = f"Model: {model_name}\nAnalysis for CVE: {cve} (from CSV Row {index})\n"
            analysis_content += "="*80 + "\n\n"
            analysis_content += "[Vulnerability Analysis]:\n" + llm_results.get('vulnerability_analysis', 'Error') + "\n\n"
            analysis_content += "[Suggested Patch]:\n" + patched_code_raw + "\n\n" # Use raw for MD file
            analysis_content += "[Patch Explanation]:\n" + llm_results.get('patch_explanation', 'Error') + "\n\n"
            
            try:
                with open(output_md_filename, 'w', encoding='utf-8') as f:
                    f.write(analysis_content)
                print(f"\n[+] Analysis MD file saved to: {output_md_filename}")
            except Exception as e:
                print(f"\n[!] Error saving MD file {output_md_filename}: {e}")

            # 5. Prepare data for the consolidated CSV file
            main_patched_func, helper_funcs = separate_functions(patched_code_clean, f_name)
            
            new_csv_row = row.to_dict()
            new_csv_row['MODEL_NAME'] = model_name # <-- Key for the benchmark
            new_csv_row['P_FUNCTION'] = main_patched_func
            new_csv_row['CHANGES'] = llm_results.get('patch_explanation', 'Error')
            new_csv_row['RUNTIME_S'] = llm_results.get('runtime_s', 0.0) # <-- Key for the benchmark
            new_csv_row['VULN_TYPE'] = extract_vuln_type(llm_results.get('vulnerability_analysis', '')) # <-- Key for the benchmark
            
            # Add dynamic helper function columns
            if helper_funcs:
                print(f"  [+] Separated {len(helper_funcs)} helper function(s).")
                for i, helper in enumerate(helper_funcs):
                    new_csv_row[f'FUNCTION_{i+1}'] = helper
            
            csv_results_list.append(new_csv_row)
            print("="*80)


    # 6. Save the consolidated CSV file
    if not csv_results_list:
        print("\n[WARNING] No analysis data was collected. Exiting.")
        sys.exit(0)
        
    output_df = pd.DataFrame(csv_results_list)
    
    # --- REVISED COLUMN ORDERING ---
    original_columns = df.columns.tolist()
    
    # Define the new static columns
    new_static_cols = ['MODEL_NAME', 'VULN_TYPE', 'RUNTIME_S', 'P_FUNCTION', 'CHANGES']
    
    # Get all dynamic helper columns (FUNCTION_1, FUNCTION_2, etc.)
    all_cols = output_df.columns.tolist()
    helper_cols = sorted([col for col in all_cols if col.startswith('FUNCTION_')], 
                         key=lambda x: int(x.split('_')[1]))
    
    # Final order
    final_columns = original_columns + new_static_cols + helper_cols
    output_df = output_df.reindex(columns=final_columns)
    # --- END REVISED ORDERING ---
    
    # Save the new DataFrame to the output CSV
    try:
        output_df.to_csv(OUTPUT_CSV_PATH, sep=';', index=False, encoding='utf-8')
        print(f"\n[SUCCESS] Analysis complete.")
        print(f"Consolidated CSV saved to: {OUTPUT_CSV_PATH}")
    except Exception as e:
        print(f"\n[ERROR] Could not save output CSV: {e}")
        
    # 7. Generate and print benchmark statistics
    generate_benchmark_stats(output_df, len(df))

if __name__ == "__main__":
    main()