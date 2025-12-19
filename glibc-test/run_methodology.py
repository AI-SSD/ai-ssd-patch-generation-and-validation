import subprocess
import os
import sys
import time

# Configuration
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SCRIPTS_DIR = os.path.join(BASE_DIR, 'scripts')

PHASES = [
    ("Phase 1: Base Replication", "phase1_base_run.py"),
    ("Phase 2: LLM Patch Generation", "phase2_patch_gen.py"),
    ("Phase 3: Patch Validation", "phase3_validation.py"),
    ("Phase 4: Documentation", "phase4_summary.py")
]

def run_phase(name, script_name):
    print(f"\n{'='*30}")
    print(f" RUNNING {name}")
    print(f"{'='*30}")
    
    script_path = os.path.join(SCRIPTS_DIR, script_name)
    if not os.path.exists(script_path):
        print(f"Error: Script {script_name} not found in {SCRIPTS_DIR}")
        return False
        
    start_time = time.time()
    try:
        # Use sys.executable to ensure we use the same python environment
        process = subprocess.Popen([sys.executable, script_name], cwd=SCRIPTS_DIR, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        
        for line in process.stdout:
            print(line, end='')
            
        process.wait()
        end_time = time.time()
        
        if process.returncode == 0:
            print(f"\n[+] {name} completed successfully in {end_time - start_time:.2f}s")
            return True
        else:
            print(f"\n[!] {name} failed with return code {process.returncode}")
            return False
    except Exception as e:
        print(f"\n[!] Error running {name}: {e}")
        return False

def main():
    print("="*50)
    print(" GLIBC VULNERABILITY PATCHING METHODOLOGY PIPELINE")
    print("="*50)
    
    overall_start = time.time()
    
    for name, script in PHASES:
        if not run_phase(name, script):
            print(f"\n[!!!] Pipeline aborted at {name}")
            sys.exit(1)
            
    overall_end = time.time()
    print(f"\n{'='*50}")
    print(f" PIPELINE COMPLETED SUCCESSFULLY")
    print(f" Total Time: {overall_end - overall_start:.2f}s")
    print(f" Final Report: {os.path.join(BASE_DIR, 'FINAL_METHODOLOGY_REPORT.md')}")
    print("="*50)

if __name__ == "__main__":
    main()
