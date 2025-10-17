"""
CVE Patch Extractor for Glibc Vulnerabilities - Git-based Version

This script uses GitPython to directly extract FULL vulnerable and patched code 
from git commits, eliminating the need for web scraping.

Key Features:
- Processes each unique P_COMMIT only once (deduplicates commits)
- Extracts ALL .c files from each commit, regardless of FilePath
- Aggregates all code changes from multiple .c files in the same commit
- **NEW**: Adds V_COMMIT column storing the parent commit (vulnerability commit)

Requirements:
- pandas
- gitpython
"""

import pandas as pd
import git
import os
import csv
from typing import Optional, Dict, List, Tuple

# Configuration
CSV_FILENAME = "dump-glibc.csv"
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_FILE = os.path.join(SCRIPT_DIR, "patched_dataset.csv")
GLIBC_REPO_URL = "https://github.com/bminor/glibc.git"
REPO_CACHE_DIR = os.path.join(SCRIPT_DIR, "glibc_repo")


def fetch_csv_data_from_local(filename: str) -> pd.DataFrame:
    """
    Read and parse a CSV file located in the same directory as this script.
    
    Args:
        filename: Name of the CSV file in the script directory
        
    Returns:
        DataFrame containing the CSV data
    """
    script_dir = os.path.dirname(os.path.abspath(__file__))
    csv_path = os.path.join(script_dir, filename)
    
    print(f"Reading CSV from local file: {csv_path}")
    
    if not os.path.exists(csv_path):
        raise FileNotFoundError(f"CSV file not found at: {csv_path}")
    
    df = pd.read_csv(csv_path)
    print(f"Loaded {len(df)} rows from CSV")
    print(f"Columns: {df.columns.tolist()}")
    return df


def setup_git_repository(repo_path: str, repo_url: str) -> git.Repo:
    """
    Clone or open the glibc git repository.
    
    Args:
        repo_path: Local path where repository should be stored
        repo_url: URL of the git repository
        
    Returns:
        GitPython Repo object
    """
    if os.path.exists(repo_path):
        print(f"Opening existing repository at {repo_path}")
        repo = git.Repo(repo_path)
        
        # Fetch latest changes
        print("Fetching latest changes from remote...")
        try:
            origin = repo.remotes.origin
            origin.fetch()
            print("Repository updated successfully")
        except Exception as e:
            print(f"Warning: Could not fetch updates: {e}")
    else:
        print(f"Cloning repository from {repo_url} to {repo_path}")
        print("This may take several minutes for the first run...")
        repo = git.Repo.clone_from(repo_url, repo_path)
        print("Repository cloned successfully")
    
    return repo


def get_full_file_content(repo: git.Repo, commit_hash: str, file_path: str) -> Optional[str]:
    """
    Get the full content of a file at a specific commit.
    
    Args:
        repo: GitPython Repo object
        commit_hash: The commit hash
        file_path: Path to the file in the repository
        
    Returns:
        Full file content as string, or None if file doesn't exist
    """
    try:
        commit = repo.commit(commit_hash)
        # Use git show to get file content at specific commit
        file_content = (commit.tree / file_path).data_stream.read()
        return file_content.decode('utf-8', errors='ignore')
    except (KeyError, AttributeError):
        # File doesn't exist at this commit
        return None
    except Exception as e:
        print(f"Error reading file {file_path} at commit {commit_hash}: {e}")
        return None


def extract_all_c_files_from_commit(repo: git.Repo, commit_hash: str) -> Tuple[Optional[str], List[Dict]]:
    """
    Extract FULL vulnerable and patched code from ALL .c files in a git commit.
    Gets the complete file content before and after the commit for every .c file.
    
    Args:
        repo: GitPython Repo object
        commit_hash: The commit hash to analyze (P_COMMIT)
        
    Returns:
        Tuple: (V_COMMIT hash, List of dicts with file_path, vulnerable_code, patched_code)
    """
    print(f"Processing commit hash: {commit_hash}")
    
    v_commit_hash: Optional[str] = None
    
    try:
        # Get the commit object (P_COMMIT)
        commit = repo.commit(commit_hash)
        
        # Get parent commit (the vulnerable version - V_COMMIT)
        if not commit.parents:
            print(f"Commit {commit_hash} has no parents (initial commit), skipping...")
            return None, []
        
        parent_commit = commit.parents[0]
        v_commit_hash = parent_commit.hexsha # Store the parent commit hash
        print(f"Parent commit (V_COMMIT): {v_commit_hash}")
        
        # Get the diff to find which files were modified
        diffs = parent_commit.diff(commit)
        
        print(f"Found {len(diffs)} file(s) changed in commit")
        
        results = []
        c_files_found = 0
        
        for diff_item in diffs:
            # Get the file path
            file_path = diff_item.b_path or diff_item.a_path
            
            if not file_path:
                continue
            
            if not file_path.endswith('.c'):
                print(f"  Skipping {file_path} (not a .c file)")
                continue
            
            c_files_found += 1
            
            # Get FULL file content from parent commit (vulnerable version)
            vulnerable_code = get_full_file_content(repo, v_commit_hash, file_path)
            
            # Get FULL file content from current commit (patched version)
            patched_code = get_full_file_content(repo, commit.hexsha, file_path)
            
            # Handle file additions/deletions
            if vulnerable_code is None and patched_code is not None:
                print(f"  ℹ {file_path}: New file added (no vulnerable version)")
                vulnerable_code = ""
            elif vulnerable_code is not None and patched_code is None:
                print(f"  ℹ {file_path}: File deleted (no patched version)")
                patched_code = ""
            elif vulnerable_code is None and patched_code is None:
                print(f"  Skipping {file_path} (file not found in either version)")
                continue
            
            result = {
                'file_path': file_path,
                'vulnerable_code': vulnerable_code,
                'patched_code': patched_code
            }
            results.append(result)
            
            vuln_lines = len(vulnerable_code.splitlines()) if vulnerable_code else 0
            patch_lines = len(patched_code.splitlines()) if patched_code else 0
            
            print(f"  ✓ {file_path}:")
            print(f"    - Vulnerable version: {vuln_lines} lines (at {v_commit_hash[:7]})")
            print(f"    - Patched version: {patch_lines} lines (at {commit_hash[:7]})")
        
        print(f"Extracted {len(results)} .c file(s) from commit (found {c_files_found} total .c files)")
        return v_commit_hash, results
    
    except git.exc.BadName:
        print(f"Error: Commit {commit_hash} not found in repository")
        return None, []
    except Exception as e:
        print(f"Error processing commit {commit_hash}: {e}")
        import traceback
        traceback.print_exc()
        return None, []


def group_cves_by_commit(df: pd.DataFrame) -> Dict[str, List[str]]:
    """
    Group CVE IDs by their P_COMMIT hash to avoid processing the same commit multiple times.
    
    Args:
        df: DataFrame with CVE and P_COMMIT columns
        
    Returns:
        Dictionary mapping commit_hash -> list of CVE IDs
    """
    commit_to_cves = {}
    
    for _, row in df.iterrows():
        commit_hash = row.get('P_COMMIT')
        cve_id = row.get('CVE')
        
        # Skip invalid entries
        if pd.isna(commit_hash) or not commit_hash or commit_hash == '\\N':
            continue
        if pd.isna(cve_id) or not cve_id:
            continue
        
        if commit_hash not in commit_to_cves:
            commit_to_cves[commit_hash] = []
        
        # Add CVE to this commit's list (avoid duplicates)
        if cve_id not in commit_to_cves[commit_hash]:
            commit_to_cves[commit_hash].append(cve_id)
    
    return commit_to_cves


def main():
    """
    Main function to orchestrate the entire extraction process.
    """
    print("=" * 80)
    print("CVE Patch Extractor - Full File Content Version")
    print("Processes each commit once, extracts ALL .c files")
    print("=" * 80)
    
    # Step 1: Load CSV data
    try:
        df = fetch_csv_data_from_local(CSV_FILENAME)
    except Exception as e:
        print(f"Error loading CSV: {e}")
        return
    
    # Display first few rows to understand structure
    print("\nFirst few rows of the CSV:")
    print(df.head())
    print(f"\nData types:")
    print(df.dtypes)
    
    # Include all rows from the CSV (do not filter by Patched)
    patched_df = df.copy()
    print(f"\nProcessing all {len(patched_df)} vulnerabilities from {len(df)} total rows")
    
    print("\nGrouping CVEs by commit hash...")
    commit_to_cves = group_cves_by_commit(patched_df)
    print(f"Found {len(commit_to_cves)} unique commits to process")
    print(f"Average CVEs per commit: {sum(len(cves) for cves in commit_to_cves.values()) / len(commit_to_cves):.2f}")
    
    # Step 2: Set up Git repository
    try:
        repo = setup_git_repository(REPO_CACHE_DIR, GLIBC_REPO_URL)
    except Exception as e:
        print(f"Error setting up repository: {e}")
        import traceback
        traceback.print_exc()
        return
    
    all_results = []
    total_commits = len(commit_to_cves)
    
    for idx, (commit_hash, cve_list) in enumerate(commit_to_cves.items(), 1):
        print(f"\n{'='*80}")
        print(f"Processing commit {idx}/{total_commits}: {commit_hash}")
        print(f"Associated CVEs: {', '.join(cve_list)}")
        print(f"{'='*80}")
        
        # Extract all .c files from this commit
        # extract_all_c_files_from_commit now returns the parent commit hash (V_COMMIT)
        v_commit, file_results = extract_all_c_files_from_commit(repo, commit_hash)
        
        if not file_results or not v_commit:
            print(f"No .c files or parent commit found for P_COMMIT {commit_hash}")
            continue
        
        for cve_id in cve_list:
            for file_result in file_results:
                result = {
                    'CVE': cve_id,
                    'V_COMMIT': v_commit,
                    'P_COMMIT': commit_hash,
                    'FilePath': file_result['file_path'],
                    'V_CODE': file_result['vulnerable_code'],
                    'P_CODE': file_result['patched_code']
                }
                all_results.append(result)
        
        print(f"Extracted {len(file_results)} .c file(s) for {len(cve_list)} CVE(s)")
        print(f"Created {len(file_results) * len(cve_list)} output rows (V_COMMIT={v_commit[:7]})")
        print(f"Progress: {len(all_results)} total rows from {idx} commits")
    
    # Step 4: Save results to CSV
    if all_results:
        print(f"\n{'='*80}")
        print(f"Saving {len(all_results)} results to {OUTPUT_FILE}")
        print(f"{'='*80}")
        
        results_df = pd.DataFrame(all_results)
        results_df.to_csv(OUTPUT_FILE, index=False, quoting=csv.QUOTE_ALL)
        
        print(f"Results saved successfully!")
        print(f"\nFinal Summary:")
        print(f"  - Total vulnerabilities in CSV: {len(df)}")
        print(f"  - Patched vulnerabilities: {len(patched_df)}")
        print(f"  - Unique commits processed: {total_commits}")
        print(f"  - Total output rows: {len(all_results)}")
        print(f"  - Unique CVEs in output: {results_df['CVE'].nunique()}")
        print(f"  - Unique .c files extracted: {results_df['FilePath'].nunique()}")
        
        # Show sample of results
        print(f"\nSample of extracted data (including V_COMMIT):")
        print(results_df[['CVE', 'P_COMMIT', 'V_COMMIT', 'FilePath']].head(10))
        
        # Show statistics about code sizes
        results_df['V_CODE_lines'] = results_df['V_CODE'].apply(lambda x: len(x.splitlines()) if x else 0)
        results_df['P_CODE_lines'] = results_df['P_CODE'].apply(lambda x: len(x.splitlines()) if x else 0)
        print(f"\nCode size statistics:")
        print(f"  - Average vulnerable code lines: {results_df['V_CODE_lines'].mean():.1f}")
        print(f"  - Average patched code lines: {results_df['P_CODE_lines'].mean():.1f}")
        print(f"  - Max vulnerable code lines: {results_df['V_CODE_lines'].max()}")
        print(f"  - Max patched code lines: {results_df['P_CODE_lines'].max()}")
    else:
        print("\nNo results to save")
        print("This could be due to:")
        print("  - Invalid commit hashes in CSV")
        print("  - Network connectivity issues during repository clone")
        print("  - All commits lacking .c file changes")
    
    print("\n" + "=" * 80)
    print("Extraction complete!")
    print("=" * 80)


if __name__ == "__main__":
    main()