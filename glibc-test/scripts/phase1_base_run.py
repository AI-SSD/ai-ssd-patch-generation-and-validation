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

# Determine if we need sudo for docker
DOCKER_PREFIX = []
try:
    subprocess.run(["docker", "ps"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
except Exception:
    print("[!] Docker seems to require sudo or is not running. Attempting to use sudo...")
    DOCKER_PREFIX = ["sudo"]

def force_remove(path):
    if os.path.exists(path):
        try:
            if os.path.isdir(path):
                shutil.rmtree(path)
            else:
                os.remove(path)
        except PermissionError:
            print(f"[!] Permission denied when removing {path}. Trying with sudo...")
            try:
                subprocess.run(['sudo', 'rm', '-rf', path], check=True)
            except subprocess.CalledProcessError:
                print(f"[!] Failed to remove {path} even with sudo.")
                sys.exit(1)

def fix_permissions(path):
    if not os.path.exists(path):
        return
    # Get current user and group
    uid = os.getuid()
    gid = os.getgid()
    
    try:
        # Try to chown (will fail if owned by root and we are not root)
        # We only check the top level directory first to see if we have access
        os.chown(path, uid, gid)
    except PermissionError:
        print(f"[!] Permission denied when accessing {path}. Fixing permissions with sudo...")
        user = os.environ.get('USER')
        if not user:
            import pwd
            user = pwd.getpwuid(uid).pw_name
            
        try:
            subprocess.run(['sudo', 'chown', '-R', f'{user}:{user}', path], check=True)
        except subprocess.CalledProcessError:
            print(f"[!] Failed to fix permissions for {path}.")

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
    force_remove(PATCHED_FILE_DEST)

    with open(PATCHED_FILE_DEST, 'w') as f:
        f.write(v_file_content)
    
    force_remove(EXPLOITS_DEST_DIR)
    shutil.copytree(EXPLOITS_SRC_DIR, EXPLOITS_DEST_DIR)

    tag = f"glibc-test:{cve_id}-base"
    
    cmd = DOCKER_PREFIX + [
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
    
    # Ensure parent directories are writable
    reports_dir = os.path.join(DOCKER_ENVS_DIR, 'collected_reports')
    if os.path.exists(reports_dir):
        fix_permissions(reports_dir)
    
    os.makedirs(collect_dir, exist_ok=True)
    fix_permissions(collect_dir)
    
    outdir = os.path.join(collect_dir, cve_id)
    
    # Clean up previous run to avoid permission errors
    force_remove(outdir)
    os.makedirs(outdir, exist_ok=True)
    
    print(f"Running base container for {cve_id}...")
    log_file = os.path.join(outdir, 'container.log')
    
    cmd = DOCKER_PREFIX + ["docker", "run", "--rm", "-v", f"{outdir}:/output", tag]
    
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
