# Save as: analyze_vulns_to_csv_and_md.py
import pandas as pd
import ollama
import sys
import os
import csv

# --- Configuration ---
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
# Input CSV file
CSV_FILE_PATH = os.path.join(SCRIPT_DIR, 'glibc_vulns_full_context.csv')

# --- Outputs ---
# 1. Directory for individual .md files
OUTPUT_MD_DIR = os.path.join(SCRIPT_DIR, 'vulnerable_analysis')
# 2. Consolidated CSV file (inside the same directory)
OUTPUT_CSV_PATH = os.path.join(OUTPUT_MD_DIR, 'glibc_vulns_analyzed.csv')

MODEL_NAME = 'qwen2.5-coder:7b'
# ---------------------

def analyze_code(client, index, cve, vulnerable_code, full_file_content):
    """
    Analyzes a vulnerable function using Ollama and returns the
    analysis, patched code, and explanation.
    
    Provides the LLM with the full file content for context, 
    but prompts it to focus on the specific function.
    
    Returns a dictionary:
    {
        "vulnerability_analysis": "...",
        "patched_code_raw": "...",
        "patch_explanation": "..."
    }
    """
    print(f"\n--- Analyzing CVE: {cve} (Row: {index}) ---")
    results = {}

    # --- Create the context string for the full file, if it exists ---
    file_context_prompt = ""
    # This check now handles 'full_file_content' being None
    if full_file_content and not pd.isna(full_file_content) and full_file_content.strip():
        file_context_prompt = f"""
    For additional context, this function is from the following full file:
    ```c
    {full_file_content}
    ```
    """
    # -----------------------------------------------------------------

    try:
        # --- Prompt 1: Analyze the vulnerability (No changes) ---
        # This prompt is correctly focused on analyzing the *problem*.
        prompt1 = f"""
        {file_context_prompt}

        Here is the specific vulnerable C function from glibc (CVE: {cve}) that you must analyze:
        ```c
        {vulnerable_code}
        ```
        Analyze *this specific function* and identify the security vulnerability.
        Explain the type of vulnerability (e.g., buffer overflow, integer overflow, use-after-free)
        and describe how it could be triggered. Do NOT generate a Proof of Concept (PoC).
        Your analysis must focus on the function provided above, using the full file for context only.
        """
        response1 = client.chat(
            model=MODEL_NAME,
            messages=[{'role': 'user', 'content': prompt1}]
        )
        vuln_analysis = response1['message']['content']
        results['vulnerability_analysis'] = vuln_analysis
        print("\n[Vulnerability Analysis]: Complete.")
        # print(vuln_analysis) # Optional: uncomment to see full analysis

        # --- Prompt 2: Generate a patch (CHANGED) ---
        # This prompt now explicitly allows for new helper functions
        # but strictly enforces the single markdown block format.
        prompt2 = f"""
        You just analyzed the following vulnerable code for {cve}:
        ```c
        {vulnerable_code}
        ```
        {file_context_prompt}

        Based on your analysis, please generate the patched C code to fix the vulnerability.

        **Your output MUST adhere to these rules:**
        1.  You **must** provide the complete, patched version of the original function (`{vulnerable_code}`).
        2.  If the fix requires creating a **new helper function**, you **must** include that new helper function in your response.
        3.  Your entire output **must** be a single C code block, enclosed in one pair of markdown backticks (```c ... ```). Place any new helper functions *before* the patched original function.

        Example format (if a new helper is needed):
        ```c
        // New helper function (if required)
        static int my_new_safe_check(char *input)
        {{
            // ... validation logic ...
        }}

        // Patched original function
        void original_function_name(char *input, ...)
        {{
            // ... patched logic ...
            if (!my_new_safe_check(input)) {{
                // ... handle error ...
            }}
            // ...
        }}
        ```
        
        Only output the code. Do not add any explanation before or after the ````c` block.
        """
        response2 = client.chat(
            model=MODEL_NAME,
            messages=[{'role': 'user', 'content': prompt2}]
        )
        # Store the raw output, including backticks, for the .md file
        patched_code_raw = response2['message']['content']
        results['patched_code_raw'] = patched_code_raw
        print("\n[Suggested Patch]: Complete.")
        # print(patched_code_raw) # Optional: uncomment to see full patch

        # --- Prompt 3: Explain the patch (CHANGED) ---
        # This prompt is updated to ask for an explanation
        # of any *new* functions that were created.
        prompt3 = f"""
        You just generated the following patch for {cve}:
        {patched_code_raw}

        This patch was for the following original vulnerable function:
        ```c
        {vulnerable_code}
        ```
        Explain the changes you made (the "diff") and why they
        effectively mitigate the vulnerability.

        - Be specific about the lines changed in the original function.
        - **If you added any new helper functions,** explain their purpose and why they were necessary for the fix.
        - Format this explanation like a git commit message or diff notes.
        """
        response3 = client.chat(
            model=MODEL_NAME,
            messages=[{'role': 'user', 'content': prompt3}]
        )
        patch_explanation = response3['message']['content']
        results['patch_explanation'] = patch_explanation
        print("\n[Patch Explanation]: Complete.")
        # print(patch_explanation) # Optional: uncomment to see full explanation
        
        return results

    except Exception as e:
        print(f"Error analyzing {cve}: {e}")
        return {
            "vulnerability_analysis": f"Error: {e}",
            "patched_code_raw": f"Error: {e}",
            "patch_explanation": f"Error: {e}"
        }

def main():
    # Increase CSV field limit for large file contents
    try:
        # Set to the maximum size supported by the system
        csv.field_size_limit(sys.maxsize)
    except OverflowError:
        # Handle potential OverflowError on 32-bit systems
        csv.field_size_limit(int(2**31 - 1))

    # Create output directory for markdown files if it doesn't exist
    if not os.path.exists(OUTPUT_MD_DIR):
        os.makedirs(OUTPUT_MD_DIR)
        print(f"Created output directory: {OUTPUT_MD_DIR}")
        
    try:
        # Load the input CSV, explicitly using semicolon as delimiter
        df = pd.read_csv(CSV_FILE_PATH, sep=';', engine='python')
        print(f"Successfully loaded '{CSV_FILE_PATH}'.")
    except FileNotFoundError:
        print(f"Error: The file '{CSV_FILE_PATH}' was not found.")
        sys.exit(1)
    except Exception as e:
        print(f"Error reading CSV: {e}")
        sys.exit(1)

    # --- CHANGED: Make V_FILE optional ---

    # Define the columns we absolutely REQUIRE
    required_input_columns = ['CVE', 'V_COMMIT', 'FilePath', 'F_NAME', 'UNIT_TYPE', 'V_FUNCTION']
    
    # Check if all REQUIRED input columns exist
    missing_cols = [col for col in required_input_columns if col not in df.columns]
    if missing_cols:
        print(f"Error: Input CSV is missing required columns: {missing_cols}")
        print(f"Available columns are: {df.columns.tolist()}")
        sys.exit(1)
        
    # Check if the optional V_FILE column exists and notify the user
    has_v_file = 'V_FILE' in df.columns
    if has_v_file:
        print("Found optional 'V_FILE' column. It will be used for context.")
    else:
        print("Optional 'V_FILE' column not found. Proceeding without full file context.")
    
    # --- END OF CHANGE ---

    try:
        client = ollama.Client()
        client.list()
        print(f"Successfully connected to Ollama. Using model: {MODEL_NAME}")
    except Exception as e:
        print("Error connecting to Ollama. Is the Ollama server running?")
        print(f"Details: {e}")
        sys.exit(1)

    # This list will store dictionaries for the new CSV
    csv_results_list = []

    # Iterate over the original dataframe (df) to have access to all columns
    for index, row in df.iterrows():
        cve = row.get('CVE', f'Row_{index}')
        v_function = row.get('V_FUNCTION')
        # Get V_FILE if it exists, otherwise it will be None
        v_file = row.get('V_FILE') if has_v_file else None

        if pd.isna(v_function) or not v_function.strip():
            print(f"Skipping row {index} (CVE: {cve}) due to missing V_FUNCTION.")
            # Add a row with skip info for the CSV
            new_row = row.to_dict() # This gets all original columns
            new_row['P_FUNCTION'] = "Skipped - Missing V_FUNCTION"
            new_row['CHANGES'] = "Skipped - Missing V_FUNCTION"
            csv_results_list.append(new_row)
            continue
            
        # 1. Analyze the code (passes v_file, which is None if not found)
        llm_results = analyze_code(client, index, cve, v_function, v_file)
        
        # --- 2. Save the individual .md file ---
        safe_cve_name = str(cve).replace('/', '_').replace('\\', '_')
        output_md_filename = os.path.join(OUTPUT_MD_DIR, f"{safe_cve_name}_Row-{index}_analysis.md")
        
        analysis_content = f"Analysis for CVE: {cve} (from CSV Row {index})\n"
        analysis_content += "="*80 + "\n\n"
        analysis_content += "[Vulnerability Analysis]:\n" + llm_results.get('vulnerability_analysis', 'Error') + "\n\n"
        # Use the raw patch output which includes markdown
        analysis_content += "[Suggested Patch]:\n" + llm_results.get('patched_code_raw', 'Error') + "\n\n"
        analysis_content += "[Patch Explanation]:\n" + llm_results.get('patch_explanation', 'Error') + "\n\n"
        
        try:
            with open(output_md_filename, 'w', encoding='utf-8') as f:
                f.write(analysis_content)
            print(f"\n[+] Analysis MD file saved to: {output_md_filename}")
        except Exception as e:
            print(f"\n[!] Error saving MD file {output_md_filename}: {e}")

        # --- 3. Prepare data for the consolidated CSV file ---
        
        # Clean the raw patch code for storage in a single CSV cell
        # (Remove backticks and surrounding whitespace)
        patched_code_clean = llm_results.get('patched_code_raw', 'Error').strip().replace('```c', '').replace('```', '').strip()
        
        # Create a new dictionary from the original row
        new_csv_row = row.to_dict()
        
        # Add the new LLM-generated columns
        new_csv_row['P_FUNCTION'] = patched_code_clean
        new_csv_row['CHANGES'] = llm_results.get('patch_explanation', 'Error')
        
        # Append the complete row to our list
        csv_results_list.append(new_csv_row)
        print("="*80)

    # --- 4. Save the consolidated CSV file ---
    
    # Define the final output columns
    # Start with all original columns from the input file
    original_columns = df.columns.tolist()
    # Add the new ones
    output_columns = original_columns + ['P_FUNCTION', 'CHANGES']
    
    # Remove duplicates (in case P_FUNCTION or CHANGES was already in the CSV)
    output_columns_final = []
    [output_columns_final.append(item) for item in output_columns if item not in output_columns_final]

    
    # Convert the list of dictionaries to a DataFrame
    output_df = pd.DataFrame(csv_results_list)
    # Re-order columns to match the new list
    output_df = output_df.reindex(columns=output_columns_final)
    
    # Save the new DataFrame to the output CSV
    try:
        output_df.to_csv(OUTPUT_CSV_PATH, sep=';', index=False, encoding='utf-8')
        print(f"\n[SUCCESS] Analysis complete.")
        print(f"Consolidated CSV saved to: {OUTPUT_CSV_PATH}")
    except Exception as e:
        print(f"\n[ERROR] Could not save output CSV: {e}")

if __name__ == "__main__":
    main()