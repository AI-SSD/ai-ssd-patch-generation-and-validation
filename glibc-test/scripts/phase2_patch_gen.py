import os
import subprocess
import sys

# Configuration
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
GLIBC_TEST_DIR = os.path.abspath(os.path.join(BASE_DIR, '..'))
PATCH_GEN_DIR = os.path.join(GLIBC_TEST_DIR, 'patch-gen')

def main():
    print("Starting Phase 2: LLM Patch Generation...")
    
    script_path = os.path.join(PATCH_GEN_DIR, 'multi-model-vuln-analyses.py')
    
    if not os.path.exists(script_path):
        print(f"Error: Script not found at {script_path}")
        sys.exit(1)
        
    try:
        # Run the existing script
        subprocess.run(["python3", "multi-model-vuln-analyses.py"], cwd=PATCH_GEN_DIR, check=True)
        print("Phase 2 completed successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Phase 2 failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
