import os
import sys
import subprocess
import re
import glob
import shutil
import pandas as pd
from collections import defaultdict

# Configuration
MAX_RETRIES = 3
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
GLIBC_TEST_DIR = os.path.abspath(os.path.join(BASE_DIR, '..'))
PATCH_GEN_DIR = os.path.join(GLIBC_TEST_DIR, 'patch-gen')
DOCKER_ENVS_DIR = os.path.join(GLIBC_TEST_DIR, 'docker-envs')
REPORTS_DIR = os.path.join(DOCKER_ENVS_DIR, 'collected_reports')
FULL_PATCH_BENCHMARK_DIR = os.path.join(PATCH_GEN_DIR, 'full_patched_files_benchmark')

# Add patch-gen to sys.path to import the analysis script
sys.path.append(PATCH_GEN_DIR)
try:
    import multi_model_vuln_analyses as patch_gen_lib
except ImportError:
    # Handle the case where the filename has hyphens which is not valid for import
    # We might need to rename it or use importlib
    import importlib.util
    spec = importlib.util.spec_from_file_location("multi_model_vuln_analyses", os.path.join(PATCH_GEN_DIR, "multi-model-vuln-analyses.py"))
    patch_gen_lib = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(patch_gen_lib)

def parse_report_folder_name(folder_name):
    """
    Parses 'glibc-test_CVE-2012-3480-v1-qwen2.5_1.5b' into components.
    Returns: (cve_folder_name, model_name)
    Example: 
    Input: glibc-test_CVE-2012-3480-v1-qwen2.5_1.5b
    Output: ('CVE-2012-3480 v1', 'qwen2.5:1.5b')
    """
    # Remove prefix
    if not folder_name.startswith('glibc-test_'):
        return None, None
    
    rest = folder_name[len('glibc-test_'):]
    
    # This is tricky because model names and CVEs can have hyphens.
    # We know the structure is {CVE_ID}-{VERSION}-{MODEL} or {CVE_ID}-{MODEL} if no version.
    # But wait, the patch-gen script generates folders like "CVE-2012-3480 v1".
    # The docker builder likely converts spaces to hyphens or underscores?
    # Let's look at the workspace info.
    # Workspace: glibc-test_CVE-2012-3480-v1-qwen2.5_1.5b
    # Patch Gen: CVE-2012-3480 v1
    
    # It seems the builder replaces " " with "-" or just concatenates.
    # Let's try to match against known directories in FULL_PATCH_BENCHMARK_DIR.
    
    available_cve_folders = [d for d in os.listdir(FULL_PATCH_BENCHMARK_DIR) if os.path.isdir(os.path.join(FULL_PATCH_BENCHMARK_DIR, d))]
    
    matched_cve_folder = None
    remaining_suffix = None
    
    # Sort by length descending to match longest prefix first
    available_cve_folders.sort(key=len, reverse=True)
    
    for cve_folder in available_cve_folders:
        # The builder likely replaces spaces with hyphens for the docker name
        normalized_cve_folder = cve_folder.replace(' ', '-')
        if rest.startswith(normalized_cve_folder):
            matched_cve_folder = cve_folder
            remaining_suffix = rest[len(normalized_cve_folder):]
            break
            
    if not matched_cve_folder:
        # Try without version (maybe it's just CVE-XXXX-XXXX)
        # If the folder in benchmark is "CVE-2014-5119" (no version)
        pass

    if matched_cve_folder and remaining_suffix:
        # remaining_suffix should be "-{MODEL}"
        # e.g. "-qwen2.5_1.5b"
        if remaining_suffix.startswith('-'):
            model_part = remaining_suffix[1:]
            # The model name in the folder uses underscores instead of colons usually
            # e.g. qwen2.5_1.5b -> qwen2.5:1.5b
            # We need to map it back to the model name used in the API.
            # Let's look at MODEL_NAMES in patch_gen_lib
            
            # Heuristic: replace last underscore with colon if it looks like a size?
            # Or just fuzzy match against known models.
            known_models = patch_gen_lib.MODEL_NAMES # ['qwen2.5-coder:1.5b', ...]
            
            for km in known_models:
                # Normalized known model: qwen2.5-coder:1.5b -> qwen2.5-coder_1.5b
                norm_km = km.replace(':', '_')
                if model_part == norm_km:
                    return matched_cve_folder, km
                    
    return None, None

def get_vulnerable_code_info(cve_folder):
    """
    Retrieves vulnerable code and file content for a given CVE folder.
    Reads from file-function.csv.
    """
    # We need to map "CVE-2012-3480 v1" back to the row in CSV.
    # This is hard because "v1" implies there are multiple rows for the same CVE.
    # We need to reload the CSV and reconstruct the versioning logic.
    
    df = pd.read_csv(patch_gen_lib.CSV_FILE_PATH, sep=';', engine='python')
    cve_counts_total = df['CVE'].value_counts().to_dict()
    current_cve_versions = defaultdict(int)
    
    target_cve = cve_folder.split(' ')[0] # "CVE-2012-3480"
    target_version = 1
    if ' v' in cve_folder:
        target_version = int(cve_folder.split(' v')[1])
        
    found_row = None
    
    for index, row in df.iterrows():
        original_cve = row.get('CVE', f'Row_{index}')
        current_cve_versions[original_cve] += 1
        
        if original_cve == target_cve:
            if cve_counts_total.get(original_cve, 0) > 1:
                if current_cve_versions[original_cve] == target_version:
                    found_row = row
                    break
            else:
                # If only 1 version, it matches
                found_row = row
                break
                
    return found_row

def run_validation():
    print("\n[Loop] Running Phase 3 Validation...")
    try:
        subprocess.run(["python3", "phase3_validation.py"], cwd=os.path.join(BASE_DIR), check=True)
        return True
    except subprocess.CalledProcessError:
        print("[Loop] Validation script returned error (some tests failed).")
        return False

def main():
    print("="*50)
    print(" STARTING ITERATIVE REPAIR LOOP")
    print("="*50)
    
    for attempt in range(1, MAX_RETRIES + 1):
        print(f"\n\n>>> ITERATION {attempt}/{MAX_RETRIES}")
        
        # 1. Run Validation
        run_validation()
        
        # 2. Analyze Results
        print("\n[Loop] Analyzing Reports...")
        failed_cases = []
        
        # Check all report folders
        report_folders = glob.glob(os.path.join(REPORTS_DIR, "glibc-test_*"))
        
        all_passed = True
        
        for report_folder in report_folders:
            folder_name = os.path.basename(report_folder)
            
            # Skip base runs
            if folder_name.endswith('-base'):
                continue
                
            # Parse folder name
            cve_folder, model_name = parse_report_folder_name(folder_name)
            if not cve_folder or not model_name:
                print(f"  [!] Could not parse folder: {folder_name}")
                continue
                
            # Find report file
            report_files = glob.glob(os.path.join(report_folder, "report_*.txt"))
            if not report_files:
                print(f"  [!] No report file in {folder_name}")
                continue
                
            report_file = report_files[0]
            with open(report_file, 'r') as f:
                content = f.read()
                
            # Check status
            if "STATUS: BUILD_FAILED" in content or "STATUS: VULNERABLE" in content or "STATUS: SCRIPT_CRASH" in content:
                all_passed = False
                print(f"  [x] Failure detected: {cve_folder} | {model_name}")
                failed_cases.append({
                    'cve_folder': cve_folder,
                    'model_name': model_name,
                    'report_content': content,
                    'report_path': report_file
                })
            else:
                # print(f"  [v] Success: {cve_folder} | {model_name}")
                pass
                
        if all_passed:
            print("\n[Loop] ALL PATCHES SUCCESSFUL! Stopping loop.")
            break
            
        if attempt == MAX_RETRIES:
            print("\n[Loop] Max retries reached. Stopping.")
            break
            
        # 3. Repair Failed Cases
        print(f"\n[Loop] Attempting to repair {len(failed_cases)} failed cases...")
        
        for case in failed_cases:
            cve_folder = case['cve_folder']
            model_name = case['model_name']
            error_log = case['report_content']
            
            # Get original info
            row = get_vulnerable_code_info(cve_folder)
            if row is None:
                print(f"  [!] Could not find CSV row for {cve_folder}")
                continue
                
            vulnerable_code = row.get('V_FUNCTION')
            v_file_content = row.get('V_FILE')
            cve_id = row.get('CVE')
            
            # Get previous patch
            # We need to find the patched file in FULL_PATCH_BENCHMARK_DIR
            # Structure: FULL_PATCH_BENCHMARK_DIR / cve_folder / model_folder / filename
            model_folder = model_name.replace(':', '_')
            patch_dir = os.path.join(FULL_PATCH_BENCHMARK_DIR, cve_folder, model_folder)
            
            if not os.path.exists(patch_dir):
                print(f"  [!] Patch directory not found: {patch_dir}")
                continue
                
            # There should be one C file here (usually)
            c_files = glob.glob(os.path.join(patch_dir, "*.c"))
            if not c_files:
                print(f"  [!] No C file found in {patch_dir}")
                continue
                
            patch_file_path = c_files[0]
            with open(patch_file_path, 'r') as f:
                previous_patch_full_content = f.read()
                
            # NOTE: The 'previous_patch' passed to LLM should ideally be just the function, 
            # but we only have the full file here easily. 
            # Passing the full file as "Previous Patch" might be too much context or confusing.
            # However, extracting just the function from the full file is hard without a parser.
            # Let's try to pass the full file content if it's not too huge, or just the error log 
            # and ask it to regenerate based on the original vulnerable code + error.
            # Actually, the `repair_code` function expects `previous_patch`.
            # Let's pass the full file content as the previous patch, but label it clearly.
            
            # Call Repair
            fixed_code_raw = patch_gen_lib.repair_code(
                model_name=model_name,
                cve=cve_id,
                vulnerable_code=vulnerable_code,
                previous_patch=previous_patch_full_content, # Passing full file
                error_log=error_log,
                full_file_content=v_file_content
            )
            
            # Extract clean code
            code_block_match = re.search(r'```c\s*(.*?)\s*```', fixed_code_raw, re.DOTALL | re.IGNORECASE)
            if code_block_match:
                fixed_code_clean = code_block_match.group(1).strip()
            else:
                fixed_code_clean = fixed_code_raw.strip().replace('```c', '').replace('```', '').strip()
                
            if "Error:" in fixed_code_clean:
                print(f"  [!] Repair failed for {cve_folder}: {fixed_code_clean}")
                continue
                
            # Save the new patch
            # We need to inject this snippet into the original file again?
            # OR if the LLM returned the full file (unlikely with current prompt), save it.
            # The prompt asks for "single C code block" of the function.
            # So we need to re-inject it into the original file.
            
            # Re-use save_aggregated_file logic?
            # We have `v_file_content` (original full file).
            # We have `vulnerable_code` (original function).
            # We have `fixed_code_clean` (new function).
            
            # We can manually do the replacement here.
            new_full_content = v_file_content
            if vulnerable_code in new_full_content:
                new_full_content = new_full_content.replace(vulnerable_code, fixed_code_clean)
            elif vulnerable_code.strip() in new_full_content:
                new_full_content = new_full_content.replace(vulnerable_code.strip(), fixed_code_clean)
            else:
                # Fallback
                new_full_content += f"\n\n/* REPAIR INJECTION */\n{fixed_code_clean}"
                
            # Overwrite the file
            try:
                with open(patch_file_path, 'w') as f:
                    f.write(new_full_content)
                print(f"  [+] Patched file updated: {patch_file_path}")
            except PermissionError:
                print(f"  [!] Permission denied when writing to {patch_file_path}")
                print(f"  [!] Please run 'sudo ./setup/fix_permissions.sh' to fix file ownership.")
                continue

if __name__ == "__main__":
    main()
