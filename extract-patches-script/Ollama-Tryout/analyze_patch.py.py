# Save as: analyze_patch_save_unique.py
import pandas as pd
import ollama
import sys
import os

# --- Configuration ---
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CSV_FILE_PATH = os.path.join(SCRIPT_DIR, 'glibc_vulns.csv')
OUTPUT_DIR = os.path.join(SCRIPT_DIR, 'patch_analysis')
MODEL_NAME = 'qwen2.5-coder:7b'
# ---------------------

# CHANGED: Added 'index' as a parameter
def analyze_diff(client, index, cve, v_function, p_function, changes):
    """
    Analyzes the difference between vulnerable and patched code and saves the output.
    """
    print(f"\n--- Analyzing Patch for CVE: {cve} (Row: {index}) ---")

    safe_cve_name = cve.replace('/', '_')
    # CHANGED: Added the row index to the filename to make it unique
    output_filename = os.path.join(OUTPUT_DIR, f"{safe_cve_name}_Row-{index}_diff_analysis.md")

    try:
        prompt = f"""
        I am analyzing a security patch for glibc (CVE: {cve}).
        Here is the vulnerable function:
        [VULNERABLE CODE]
        ```c
        {v_function}
        ```

        Here is the patched function:
        [PATCHED CODE]
        ```c
        {p_function}
        ```

        And here is the 'CHANGES' description from the commit:
        [CHANGES]
        {changes}

        Based on all this information, please do the following:
        1.  Identify and explain the original security vulnerability.
        2.  Describe exactly what changed between the vulnerable and patched code.
        3.  Explain how these changes fix the vulnerability.
        Do NOT generate a Proof of Concept (PoC).
        """
        response = client.chat(
            model=MODEL_NAME,
            messages=[{'role': 'user', 'content': prompt}]
        )
        
        analysis_content = response['message']['content']
        print("\n[Patch and Vulnerability Analysis]:")
        print(analysis_content)
        
        with open(output_filename, 'w', encoding='utf-8') as f:
            f.write(f"Patch Analysis for CVE: {cve} (from CSV Row {index})\n")
            f.write("="*80 + "\n\n")
            f.write(analysis_content)
        print(f"\n[+] Analysis saved to: {output_filename}")

    except Exception as e:
        print(f"Error analyzing {cve}: {e}")

def main():
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)
        print(f"Created output directory: {OUTPUT_DIR}")

    try:
        df = pd.read_csv(CSV_FILE_PATH, sep=None, engine='python')
    except FileNotFoundError:
        print(f"Error: The file '{CSV_FILE_PATH}' was not found.")
        sys.exit(1)
    
    try:
        client = ollama.Client()
        client.list() 
    except Exception as e:
        print("Error connecting to Ollama. Is the Ollama server running?")
        sys.exit(1)

    print(f"Successfully connected to Ollama. Using model: {MODEL_NAME}")

    for index, row in df.iterrows():
        cve = row.get('CVE', f'Row_{index}')
        v_function = row.get('V_FUNCTION')
        p_function = row.get('P_FUNCTION')
        changes = row.get('CHANGES')

        if (pd.isna(v_function) or pd.isna(p_function) or
            not v_function.strip() or not p_function.strip()):
            print(f"Skipping row {index} (CVE: {cve}) due to missing V_FUNCTION or P_FUNCTION.")
            continue
            
        # CHANGED: Passed the 'index' to the function
        analyze_diff(client, index, cve, v_function, p_function, changes)
        print("="*80)

if __name__ == "__main__":
    main()