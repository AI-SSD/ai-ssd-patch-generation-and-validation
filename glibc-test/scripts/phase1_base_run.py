import os
import csv
import shutil
import subprocess
import sys

# Configuration
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
GLIBC_TEST_DIR = os.path.abspath(os.path.join(BASE_DIR, '..'))
PATCH_GEN_DIR = os.path.join(GLIBC_TEST_DIR, 'patch-gen')
DOCKER_ENVS_DIR = os.path.join(GLIBC_TEST_DIR, 'docker-envs')
CSV_FILE = os.path.join(PATCH_GEN_DIR, 'file-function.csv')
EXPLOITS_SRC_DIR = os.path.join(PATCH_GEN_DIR, 'exploits')
EXPLOITS_DEST_DIR = os.path.join(DOCKER_ENVS_DIR, 'exploits')
PATCHED_FILE_DEST = os.path.join(DOCKER_ENVS_DIR, 'patched.c')

def load_cve_info(csv_path):
    cve_info = {}
    with open(csv_path, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f, delimiter=';')
        for row in reader:
            cve = row['CVE']
            if cve not in cve_info:
                cve_info[cve] = {
                    'commit': row['V_COMMIT'],
                    'filepath': row['FilePath'],
                    'v_file': row['V_FILE']
                }
    return cve_info

def build_base_image(cve_id, cve_data):
    commit = cve_data['commit']
    target_filepath = cve_data['filepath']
    v_file_content = cve_data['v_file']
    
    print(f"Building BASE image for {cve_id}...")
    
    # Save the original file as 'patched.c' to build the vulnerable version
    with open(PATCHED_FILE_DEST, 'w') as f:
        f.write(v_file_content)
    
    if os.path.exists(EXPLOITS_DEST_DIR):
        shutil.rmtree(EXPLOITS_DEST_DIR)
    shutil.copytree(EXPLOITS_SRC_DIR, EXPLOITS_DEST_DIR)

    tag = f"glibc-test:{cve_id}-base"
    
    cmd = [
        "docker", "build",
        "--build-arg", f"GIT_COMMIT={commit}",
        "--build-arg", f"CVE={cve_id}",
        "--build-arg", f"MODEL=base",
        "--build-arg", f"TARGET_FILE_PATH={target_filepath}",
        "-t", tag,
        "."
    ]
    
    try:
        subprocess.run(cmd, check=True, cwd=DOCKER_ENVS_DIR)
        print(f"Successfully built {tag}")
        return tag
    except subprocess.CalledProcessError as e:
        print(f"Failed to build {tag}: {e}")
        return None
    finally:
        if os.path.exists(PATCHED_FILE_DEST):
            os.remove(PATCHED_FILE_DEST)

def run_base_container(tag, cve_id):
    collect_dir = os.path.join(DOCKER_ENVS_DIR, 'collected_reports', 'base_runs')
    os.makedirs(collect_dir, exist_ok=True)
    
    outdir = os.path.join(collect_dir, cve_id)
    os.makedirs(outdir, exist_ok=True)
    
    print(f"Running base container for {cve_id}...")
    log_file = os.path.join(outdir, 'container.log')
    
    cmd = ["docker", "run", "--rm", "-v", f"{outdir}:/output", tag]
    
    try:
        with open(log_file, 'w') as f:
            subprocess.run(cmd, check=True, stdout=f, stderr=subprocess.STDOUT)
        print(f"Base run completed for {cve_id}. Results in {outdir}")
    except subprocess.CalledProcessError as e:
        print(f"Base run failed for {cve_id} (this might be expected if it crashes).")

def main():
    if not os.path.exists(CSV_FILE):
        print(f"Error: CSV file not found at {CSV_FILE}")
        return

    cve_data = load_cve_info(CSV_FILE)
    
    # For Phase 1, we only need to run each CVE once (base version)
    for cve_id, data in cve_data.items():
        tag = build_base_image(cve_id, data)
        if tag:
            run_base_container(tag, cve_id)

if __name__ == "__main__":
    main()
