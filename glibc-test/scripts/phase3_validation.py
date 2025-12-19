import os
import subprocess
import sys
import shutil

# Configuration
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
GLIBC_TEST_DIR = os.path.abspath(os.path.join(BASE_DIR, '..'))
DOCKER_ENVS_DIR = os.path.join(GLIBC_TEST_DIR, 'docker-envs')
PATCH_GEN_DIR = os.path.join(GLIBC_TEST_DIR, 'patch-gen')

def main():
    print("Starting Phase 3: Validation (Build & Run)...")
    
    # 0. Copy patches to docker-envs
    print("\n--- Step 3.0: Copying patches to docker-envs ---")
    src_patches = os.path.join(PATCH_GEN_DIR, 'full_patched_files_benchmark')
    dest_patches = os.path.join(DOCKER_ENVS_DIR, 'patches')
    
    if os.path.exists(src_patches):
        if os.path.exists(dest_patches):
            shutil.rmtree(dest_patches)
        shutil.copytree(src_patches, dest_patches)
        print(f"Copied {src_patches} to {dest_patches}")
    else:
        print(f"Warning: Source patches not found at {src_patches}")

    # 1. Build Images
    print("\n--- Step 3.1: Building Patched Images ---")
    try:
        subprocess.run(["python3", "builder.py"], cwd=DOCKER_ENVS_DIR, check=True)
        print("Build step completed.")
    except subprocess.CalledProcessError as e:
        print(f"Build step failed: {e}")
        sys.exit(1)
        
    # 2. Run Containers
    print("\n--- Step 3.2: Running Validation Containers ---")
    try:
        # Ensure the script is executable
        subprocess.run(["chmod", "+x", "run_all_images.sh"], cwd=DOCKER_ENVS_DIR, check=True)
        subprocess.run(["./run_all_images.sh"], cwd=DOCKER_ENVS_DIR, check=True)
        print("Run step completed.")
    except subprocess.CalledProcessError as e:
        print(f"Run step failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
