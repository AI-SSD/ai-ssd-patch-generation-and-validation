import subprocess
import os
import sys
import time

# Configuration
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PATCH_GEN_DIR = os.path.join(BASE_DIR, 'patch-gen')
DOCKER_ENVS_DIR = os.path.join(BASE_DIR, 'docker-envs')

def run_step(name, command, cwd):
    print(f"\n{'='*20} STARTING {name} {'='*20}")
    start_time = time.time()
    try:
        # Use shell=True for scripts, or list for python
        if isinstance(command, str):
            process = subprocess.Popen(command, shell=True, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        else:
            process = subprocess.Popen(command, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        
        for line in process.stdout:
            print(line, end='')
        
        process.wait()
        if process.returncode != 0:
            print(f"\n[!] {name} failed with return code {process.returncode}")
            return False
            
        end_time = time.time()
        print(f"\n[+] {name} completed in {end_time - start_time:.2f} seconds.")
        return True
    except Exception as e:
        print(f"\n[!] Error running {name}: {e}")
        return False

def main():
    print("Starting Automated Patch Generation and Validation Pipeline")
    print(f"Base Directory: {BASE_DIR}")

    # Phase 2: Automated Patch Gen (GenAI)
    # Note: This uses an external API for LLM generation.
    if not run_step("Phase 2: LLM Patch Generation", ["python3", "multi-model-vuln-analyses.py"], PATCH_GEN_DIR):
        print("Pipeline aborted at Phase 2.")
        sys.exit(1)

    # Phase 3: Setup (Build Docker Images)
    if not run_step("Phase 3: Build Docker Images", ["python3", "builder.py"], DOCKER_ENVS_DIR):
        print("Pipeline aborted at Phase 3 (Build).")
        sys.exit(1)

    # Phase 3: Validation (Run Containers)
    if not run_step("Phase 3: Run Validation", "./run_all_images.sh", DOCKER_ENVS_DIR):
        print("Pipeline aborted at Phase 3 (Run).")
        sys.exit(1)

    # Phase 4: Documentation / Summary
    summary_path = os.path.join(DOCKER_ENVS_DIR, 'collected_reports', 'summary.txt')
    if os.path.exists(summary_path):
        print(f"\n{'='*20} PIPELINE COMPLETE {'='*20}")
        print(f"Final summary available at: {summary_path}")
        
        # Optional: Print a snippet of the summary
        with open(summary_path, 'r') as f:
            lines = f.readlines()
            print(f"Summary contains {len(lines)} lines of results.")
    else:
        print("\n[!] Pipeline finished but summary.txt was not found.")

if __name__ == "__main__":
    main()
