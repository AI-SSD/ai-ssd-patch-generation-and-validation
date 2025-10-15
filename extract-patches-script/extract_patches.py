"""
CVE Patch Extractor for Glibc Vulnerabilities - Selenium Version with Bot Detection Bypass

This script uses undetected-chromedriver to bypass bot detection on sourceware.org
and extract vulnerable and patched code snippets from CVE vulnerability data.

Requirements:
- pandas
- undetected-chromedriver
- selenium
- beautifulsoup4
"""

import pandas as pd
import undetected_chromedriver as uc
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from bs4 import BeautifulSoup
import time
import csv
from typing import Optional, Dict, Tuple, List
import os
import re

# Configuration
CSV_FILENAME = "dump-glibc.csv"
OUTPUT_FILE = "patched_dataset.csv"

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

def setup_driver() -> uc.Chrome:
    """
    Set up undetected Chrome driver with options to bypass bot detection.
    
    Returns:
        Configured Chrome driver instance
    """
    print("Setting up undetected Chrome driver...")
    
    options = uc.ChromeOptions()
    
    # Additional options to appear more like a real browser
    options.add_argument('--disable-blink-features=AutomationControlled')
    options.add_argument('--disable-dev-shm-usage')
    options.add_argument('--no-sandbox')
    options.add_argument('--disable-gpu')
    
    # Create driver with undetected-chromedriver
    driver = uc.Chrome(options=options, version_main=None)
    
    # Set page load timeout
    driver.set_page_load_timeout(30)
    
    print("Driver setup complete")
    return driver

def extract_file_path_from_header(header_div) -> Optional[str]:
    """
    Extract file path from diff header.
    
    Args:
        header_div: BeautifulSoup div element with class 'diff header'
        
    Returns:
        Extracted file path or None
    """
    if not header_div:
        return None
    
    header_text = header_div.get_text()
    
    # Try to extract file path from patterns like "a/path/to/file.c b/path/to/file.c"
    # The file path is typically after "a/" or "b/"
    match = re.search(r'[ab]/([\w/\.\-]+)', header_text)
    if match:
        return match.group(1)
    
    return None

def extract_code_from_patch_section(patch_div) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """
    Extract vulnerable and patched code from a single patch section (one file).
    
    Args:
        patch_div: BeautifulSoup div element with class 'patch'
        
    Returns:
        Tuple of (file_path, vulnerable_code, patched_code)
    """
    # Extract file path from header
    header_div = patch_div.find('div', class_='diff header')
    file_path = extract_file_path_from_header(header_div)
    
    vulnerable_lines = []
    patched_lines = []
    
    # Find all diff line divs within this patch
    all_divs = patch_div.find_all('div', class_=True)
    
    for div in all_divs:
        classes = div.get('class', [])
        
        # Only process lines with 'diff' class
        if 'diff' not in classes:
            continue
        
        # Skip headers and metadata
        if any(x in classes for x in ['header', 'chunk_header', 'extended_header', 'from_file', 'to_file']):
            continue
        
        line_text = div.get_text()
        
        # Context lines (common to both versions) - class contains both 'diff' and 'ctx'
        if 'ctx' in classes:
            vulnerable_lines.append(line_text)
            patched_lines.append(line_text)
        # Removed lines (vulnerable code only) - class contains both 'diff' and 'rem'
        elif 'rem' in classes:
            vulnerable_lines.append(line_text)
        # Added lines (patched code only) - class contains both 'diff' and 'add'
        elif 'add' in classes:
            patched_lines.append(line_text)
    
    # Join lines
    vulnerable_code = '\n'.join(vulnerable_lines).strip() if vulnerable_lines else None
    patched_code = '\n'.join(patched_lines).strip() if patched_lines else None
    
    return file_path, vulnerable_code, patched_code

def extract_code_from_html_diff(soup: BeautifulSoup, target_file_path: str = None) -> List[Dict]:
    """
    Extract vulnerable and patched code from HTML-formatted diff on sourceware.org.
    Returns a list of dictionaries, one per file in the commit.
    
    Args:
        soup: BeautifulSoup object of the page
        target_file_path: Optional file path to filter specific file changes
        
    Returns:
        List of dicts with keys: file_path, vulnerable_code, patched_code
    """
    results = []
    
    # Find all patch divs (each represents one file)
    patches = soup.find_all('div', class_='patch')
    
    print(f"Found {len(patches)} patch sections (files)")
    
    for patch_idx, patch in enumerate(patches, 1):
        file_path, vulnerable_code, patched_code = extract_code_from_patch_section(patch)
        
        # If target_file_path is specified, only include matching files
        if target_file_path:
            # Strip the extracted path for reliable comparison, in case of any non-visible characters
            extracted_path = file_path.strip() if file_path else "" 
            
            # Comparison: Check if the target file is a substring of the extracted path
            if not extracted_path or target_file_path not in extracted_path:
                # Improved logging to show the actual strings being compared
                print(f"  Patch {patch_idx}: Skipping (Target file '{target_file_path}' not found in extracted path '{extracted_path}')")
                continue
        
        # Only include if we extracted some code
        if vulnerable_code or patched_code:
            result = {
                'file_path': file_path or f'unknown_file_{patch_idx}',
                'vulnerable_code': vulnerable_code or '',
                'patched_code': patched_code or ''
            }
            results.append(result)
            
            print(f"  Patch {patch_idx} ({file_path or 'unknown'}):")
            print(f"    - Vulnerable: {len(vulnerable_code.splitlines()) if vulnerable_code else 0} lines")
            print(f"    - Patched: {len(patched_code.splitlines()) if patched_code else 0} lines")
        else:
            print(f"  Patch {patch_idx} ({file_path or 'unknown'}): No code extracted")
    
    return results

def extract_code_from_commit_selenium(driver: uc.Chrome, commit_hash: str, file_path: str = None) -> Tuple[List[Dict], Optional[str]]:
    """
    Extract vulnerable and patched code from a sourceware.org commit using Selenium.
    ...
    """
    print(f"Processing commit hash: {commit_hash}")
    
    # Try different URL formats
    urls = [
        f"https://sourceware.org/git/?p=glibc.git;a=commitdiff;h={commit_hash}",
    ]
    
    for url in urls:
        print(f"Trying URL: {url}")
        
        try:
            # Navigate to the URL
            driver.get(url)
            
            # Wait for page to load - consider increasing this if your connection is slow
            time.sleep(5) # Increased sleep time for safety
            
            # Get page source
            page_source = driver.page_source
            
            # Parse with BeautifulSoup
            soup = BeautifulSoup(page_source, 'html.parser')
            
            # Check if we have patch content - this is the reliable check
            patch_divs = soup.find_all('div', class_='patch')
            if not patch_divs:
                print(f"No patch divs found in page. Possible bot detection or page not loaded.")
                continue
            
            # Parse with BeautifulSoup
            soup = BeautifulSoup(page_source, 'html.parser')
            
            # Check if we have patch content
            patch_divs = soup.find_all('div', class_='patch')
            if not patch_divs:
                print(f"No patch divs found in page")
                continue
            
            print(f"Found {len(patch_divs)} patch div(s) in page")
            
            # Extract code from all files
            file_results = extract_code_from_html_diff(soup, file_path)
            
            if file_results:
                print(f"Successfully extracted code from {len(file_results)} file(s)")
                return file_results, url
            else:
                print(f"Patch divs found but no code extracted")
        
        except Exception as e:
            print(f"Error processing {url}: {e}")
            import traceback
            traceback.print_exc()
            continue
    
    print(f"Failed to extract code from any URL")
    return [], None

def process_vulnerability(driver: uc.Chrome, row: pd.Series) -> List[Dict]:
    """
    Process a single vulnerability row and extract all required information.
    
    Args:
        driver: Selenium Chrome driver instance
        row: A row from the DataFrame with columns: CVE, P_COMMIT, FilePath, Patched
        
    Returns:
        List of dictionaries with extracted data (one per file in the commit)
    """
    cve_id = row.get('CVE')
    commit_hash = row.get('P_COMMIT')
    file_path = row.get('FilePath')
    patched = row.get('Patched')
    vulnerability_url = row.get('VULNERABILITY_URL')
    
    # Validate required fields
    if pd.isna(cve_id) or not cve_id:
        print("No CVE ID found in row")
        return []
    
    print(f"\n{'='*80}")
    print(f"Processing CVE: {cve_id}")
    print(f"{'='*80}")
    
    if pd.isna(patched) or patched == 0:
        print(f"CVE {cve_id} is not patched (Patched={patched}), skipping...")
        return []
    
    if pd.isna(commit_hash) or not commit_hash or commit_hash == '\\N':
        print(f"No commit hash found for {cve_id}, skipping...")
        return []
    
    print(f"Commit hash: {commit_hash}")
    target_file = None
    if not pd.isna(file_path) and file_path and file_path != '\\N':
        print(f"Target file path: {file_path}")
        target_file = file_path
    
    if not pd.isna(vulnerability_url) and vulnerability_url:
        print(f"Vulnerability URL: {vulnerability_url}")
    
    file_results, successful_url = extract_code_from_commit_selenium(
        driver,
        commit_hash,
        target_file
    )
    
    if not file_results:
        print(f"No code extracted for {cve_id}")
        return []
    
    # Add CVE metadata to each file result
    results = []
    for file_result in file_results:
        result = {
            'cve_id': cve_id,
            'file_path': file_result['file_path'],
            'vulnerable_code': file_result['vulnerable_code'],
            'patched_code': file_result['patched_code'],
            'patch_url': successful_url or '',
            'commit_hash': commit_hash,
            'vulnerability_url': vulnerability_url or ''
        }
        results.append(result)
    
    print(f"✓ Successfully extracted code for {cve_id} from {len(results)} file(s)")
    for idx, result in enumerate(results, 1):
        vuln_lines = len(result['vulnerable_code'].splitlines()) if result['vulnerable_code'] else 0
        patch_lines = len(result['patched_code'].splitlines()) if result['patched_code'] else 0
        print(f"  File {idx} ({result['file_path']}): {vuln_lines} vuln lines, {patch_lines} patch lines")
    
    return results

def main():
    """
    Main function to orchestrate the entire extraction process.
    """
    print("=" * 80)
    print("CVE Patch Extractor - Selenium Version with Bot Detection Bypass")
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
    
    # Filter for patched vulnerabilities (Patched != 0)
    patched_df = df[df['Patched'] != 0].copy()
    print(f"\nFound {len(patched_df)} patched vulnerabilities out of {len(df)} total")
    
    # Step 2: Set up Selenium driver
    driver = None
    try:
        driver = setup_driver()
        
        # Step 3: Process each patched vulnerability
        all_results = []
        total_rows = len(patched_df)
        
        for idx, (_, row) in enumerate(patched_df.iterrows(), 1):
            print(f"\nProcessing row {idx}/{total_rows}")
            
            results = process_vulnerability(driver, row)
            all_results.extend(results)
            
            if results:
                print(f"Progress: {len(all_results)} total file extractions from {idx} CVEs")
            
            # Add delay between requests to be respectful to the server
            time.sleep(2)
        
        # Step 4: Save results to CSV
        if all_results:
            print(f"\n{'='*80}")
            print(f"Saving {len(all_results)} results to {OUTPUT_FILE}")
            print(f"{'='*80}")
            
            results_df = pd.DataFrame(all_results)
            results_df.to_csv(OUTPUT_FILE, index=False, quoting=csv.QUOTE_ALL)
            
            print(f"✓ Results saved successfully!")
            print(f"\nFinal Summary:")
            print(f"  - Total vulnerabilities in CSV: {len(df)}")
            print(f"  - Patched vulnerabilities processed: {total_rows}")
            print(f"  - Total file extractions: {len(all_results)}")
            print(f"  - Unique CVEs extracted: {results_df['cve_id'].nunique()}")
            
            # Show sample of results
            print(f"\nSample of extracted data:")
            print(results_df[['cve_id', 'commit_hash', 'file_path']].head(10))
        else:
            print("\nNo results to save")
            print("This could be due to:")
            print("  - Bot detection still active (try running without headless mode)")
            print("  - Network connectivity issues")
            print("  - Changes in website structure")
            print("  - All commits lacking extractable diffs")
    
    except Exception as e:
        print(f"Error during processing: {e}")
        import traceback
        traceback.print_exc()
    
    finally:
        # Clean up: close the browser
        if driver:
            print("\nClosing browser...")
            driver.quit()
    
    print("\n" + "=" * 80)
    print("Extraction complete!")
    print("=" * 80)

if __name__ == "__main__":
    main()