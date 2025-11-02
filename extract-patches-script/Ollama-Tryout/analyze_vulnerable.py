# Save as: analyze_vulnerable_code_save_unique.py
import pandas as pd
import ollama
import sys
import os

# --- Configuration ---
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CSV_FILE_PATH = os.path.join(SCRIPT_DIR, 'glibc_vulns.csv')
OUTPUT_DIR = os.path.join(SCRIPT_DIR, 'vulnerable_analysis')
MODEL_NAME = 'qwen2.5-coder:7b'
# ---------------------

# CHANGED: Added 'index' as a parameter
def analyze_code(client, index, cve, vulnerable_code):
    """
    Analyzes a vulnerable function using Ollama and saves the output.
    """
    print(f"\n--- Analyzing CVE: {cve} (Row: {index}) ---")
    
    safe_cve_name = cve.replace('/', '_')
    # CHANGED: Added the row index to the filename to make it unique
    output_filename = os.path.join(OUTPUT_DIR, f"{safe_cve_name}_Row-{index}_analysis.md")
    
    analysis_content = f"Analysis for CVE: {cve} (from CSV Row {index})\n"
    analysis_content += "="*80 + "\n\n"

    try:
        # Prompt 1: Analyze the vulnerability
        prompt1 = f"""
        Here is a vulnerable C function from glibc (CVE: {cve}):
        ```c
        {vulnerable_code}
        ```
        Analyze this code and identify the security vulnerability.
        Explain the type of vulnerability (e.g., buffer overflow, integer overflow, use-after-free)
        and describe how it could be triggered. Do NOT generate a Proof of Concept (PoC).
        """
        response1 = client.chat(
            model=MODEL_NAME,
            messages=[{'role': 'user', 'content': prompt1}]
        )
        vuln_analysis = response1['message']['content']
        print("\n[Vulnerability Analysis]:")
        print(vuln_analysis)
        analysis_content += "[Vulnerability Analysis]:\n" + vuln_analysis + "\n\n"

        # Prompt 2: Generate a patch
        prompt2 = f"""
        Based on the vulnerability you just identified in the code for {cve},
        please generate a patched version of the function that fixes the security flaw.
        Only output the patched C code.
        """
        response2 = client.chat(
            model=MODEL_NAME,
            messages=[{'role': 'user', 'content': prompt2}]
        )
        patched_code = response2['message']['content']
        print("\n[Suggested Patch]:")
        print(patched_code)
        analysis_content += "[Suggested Patch]:\n" + patched_code + "\n\n"

        # Prompt 3: Explain the patch
        prompt3 = f"""
        Explain the changes you made in the patched code and why they
        effectively mitigate the vulnerability for {cve}.
        """
        response3 = client.chat(
            model=MODEL_NAME,
            messages=[{'role': 'user', 'content': prompt3}]
        )
        patch_explanation = response3['message']['content']
        print("\n[Patch Explanation]:")
        print(patch_explanation)
        analysis_content += "[Patch Explanation]:\n" + patch_explanation + "\n\n"
        
        with open(output_filename, 'w', encoding='utf-8') as f:
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

        if pd.isna(v_function) or not v_function.strip():
            print(f"Skipping row {index} (CVE: {cve}) due to missing V_FUNCTION.")
            continue
            
        # CHANGED: Passed the 'index' to the function
        analyze_code(client, index, cve, v_function)
        print("="*80)

if __name__ == "__main__":
    main()