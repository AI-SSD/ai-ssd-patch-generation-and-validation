import os
import csv
import shutil
import subprocess
import sys

# Configuration
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PATCH_GEN_DIR = os.path.abspath(os.path.join(BASE_DIR, '../patch-gen'))
CSV_FILE = os.path.join(PATCH_GEN_DIR, 'file-function.csv')
PATCHES_DIR = os.path.join(PATCH_GEN_DIR, 'full_patched_files_benchmark')
EXPLOITS_SRC_DIR = os.path.join(PATCH_GEN_DIR, 'exploits')
EXPLOITS_DEST_DIR = os.path.join(BASE_DIR, 'exploits')
PATCHED_FILE_DEST = os.path.join(BASE_DIR, 'patched.c')

def load_cve_info(csv_path):
    cve_info = {}
    with open(csv_path, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f, delimiter=';')
        for row in reader:
            cve = row['CVE']
            if cve not in cve_info:
                cve_info[cve] = {
                    'commit': row['COMMIT'],
                    'filepath': row['FilePath']
                }
    return cve_info

def build_image(cve_folder_name, model, patched_file_path, cve_data):
    cve_id = cve_folder_name.split(' ')[0]
    
    if cve_id not in cve_data:
        print(f"Warning: No data found for {cve_id} in CSV. Skipping.")
        return

    commit = cve_data[cve_id]['commit']
    target_filepath = cve_data[cve_id]['filepath']
    
    print(f"Building image for {cve_folder_name} / {model}...")
    print(f"  CVE: {cve_id}")
    print(f"  Commit: {commit}")
    print(f"  Target File: {target_filepath}")
    print(f"  Patched File: {patched_file_path}")

    shutil.copy(patched_file_path, PATCHED_FILE_DEST)
    
    if os.path.exists(EXPLOITS_DEST_DIR):
        shutil.rmtree(EXPLOITS_DEST_DIR)
    shutil.copytree(EXPLOITS_SRC_DIR, EXPLOITS_DEST_DIR)

    tag_cve = cve_folder_name.replace(' ', '-')
    tag = f"glibc-test:{tag_cve}-{model}"
    
    cmd = [
        "docker", "build",
        "--build-arg", f"GIT_COMMIT={commit}",
        "--build-arg", f"CVE={cve_id}",
        "--build-arg", f"MODEL={model}",
        "--build-arg", f"TARGET_FILE_PATH={target_filepath}",
        "-t", tag,
        "."
    ]
    
    try:
        subprocess.run(cmd, check=True, cwd=BASE_DIR)
        print(f"Successfully built {tag}")
    except subprocess.CalledProcessError as e:
        print(f"Failed to build {tag}: {e}")
    finally:
        # Cleanup
        if os.path.exists(PATCHED_FILE_DEST):
            os.remove(PATCHED_FILE_DEST)
        if os.path.exists(EXPLOITS_DEST_DIR):
            shutil.rmtree(EXPLOITS_DEST_DIR)

def main():
    if not os.path.exists(CSV_FILE):
        print(f"Error: CSV file not found at {CSV_FILE}")
        return

    cve_data = load_cve_info(CSV_FILE)
    
    if not os.path.exists(PATCHES_DIR):
        print(f"Error: Patches directory not found at {PATCHES_DIR}")
        return

    for cve_folder in os.listdir(PATCHES_DIR):
        cve_path = os.path.join(PATCHES_DIR, cve_folder)
        if not os.path.isdir(cve_path):
            continue
            
        for model_folder in os.listdir(cve_path):
            model_path = os.path.join(cve_path, model_folder)
            if not os.path.isdir(model_path):
                continue
                
            patched_files = [f for f in os.listdir(model_path) if f.endswith('.c')]
            if not patched_files:
                print(f"Warning: No .c file found in {model_path}")
                continue
            
            patched_file = patched_files[0]
            patched_file_path = os.path.join(model_path, patched_file)
            
            build_image(cve_folder, model_folder, patched_file_path, cve_data)

if __name__ == "__main__":
    main()
