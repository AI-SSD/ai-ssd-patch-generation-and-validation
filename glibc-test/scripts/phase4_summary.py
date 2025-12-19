import os
import re

# Configuration
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
GLIBC_TEST_DIR = os.path.abspath(os.path.join(BASE_DIR, '..'))
COLLECT_DIR = os.path.join(GLIBC_TEST_DIR, 'docker-envs', 'collected_reports')
OUTPUT_FILE = os.path.join(GLIBC_TEST_DIR, 'FINAL_METHODOLOGY_REPORT.md')

def parse_report(file_path):
    results = {}
    try:
        with open(file_path, 'r') as f:
            content = f.read()
            results['CVE'] = re.search(r'CVE: (.*)', content).group(1)
            results['STATUS'] = re.search(r'STATUS: (.*)', content).group(1)
            # Extract more if needed
    except Exception:
        pass
    return results

def main():
    print("Starting Phase 4: Documentation...")
    
    if not os.path.exists(COLLECT_DIR):
        print(f"Error: Collected reports directory not found at {COLLECT_DIR}")
        return

    report_md = "# Methodology Validation Report\n\n"
    
    # Base Runs
    report_md += "## Phase 1: Base Replication (Vulnerable Baseline)\n"
    base_dir = os.path.join(COLLECT_DIR, 'base_runs')
    if os.path.exists(base_dir):
        report_md += "| CVE | Status |\n| --- | --- |\n"
        for cve_id in sorted(os.listdir(base_dir)):
            cve_path = os.path.join(base_dir, cve_id)
            if os.path.isdir(cve_path):
                # Find report_*.txt
                for f in os.listdir(cve_path):
                    if f.startswith('report_') and f.endswith('.txt'):
                        res = parse_report(os.path.join(cve_path, f))
                        report_md += f"| {res.get('CVE', cve_id)} | {res.get('STATUS', 'Unknown')} |\n"
    else:
        report_md += "No base runs found.\n"

    # Patched Runs
    report_md += "\n## Phase 3: Patch Validation\n"
    report_md += "| Image (CVE-Model) | Status |\n| --- | --- |\n"
    
    for folder in sorted(os.listdir(COLLECT_DIR)):
        if folder == 'base_runs' or folder == 'summary.txt':
            continue
        
        folder_path = os.path.join(COLLECT_DIR, folder)
        if os.path.isdir(folder_path):
            for f in os.listdir(folder_path):
                if f.startswith('report_') and f.endswith('.txt'):
                    res = parse_report(os.path.join(folder_path, f))
                    report_md += f"| {folder} | {res.get('STATUS', 'Unknown')} |\n"

    with open(OUTPUT_FILE, 'w') as f:
        f.write(report_md)
        
    print(f"Final report generated at: {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
