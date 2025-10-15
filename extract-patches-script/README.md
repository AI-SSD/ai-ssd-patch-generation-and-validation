# Glibc CVE Patch Extractor

This Python script utilizes **`undetected-chromedriver` and** ****Selenium** to bypass bot detection mechanisms, specifically on** **sourceware.org** , to systematically extract vulnerable and patched code snippets from Glibc vulnerability data linked to specific CVEs.

The primary goal is to create a structured dataset of code differences (diffs) corresponding to security patches.

---

## Features

* **Bot Detection Bypass:** Uses `undetected-chromedriver` to mimic a legitimate browser, avoiding common bot detection measures.
* **Data Extraction:** Reads CVE metadata from a local CSV file (`dump-glibc.csv`).
* **Patch Snippet Retrieval:** Navigates to Glibc Git commit diffs on ` sourceware.org` and parses the HTML to extract:
  * The file path changed.
  * The **vulnerable code** (removed lines).
  * The **patched code** (added lines, including context).
* **Data Output:** Generates a structured CSV file (`patched_dataset.csv`) containing the CVE ID, commit hash, file path, patch URL, and the code snippets.
* **Targeted Extraction:** Can optionally filter the code extraction to only include changes in a specified file path.

---

## Prerequisites

Before running the script, ensure you have **Python 3.x** installed.

You will need the following libraries:

**Bash**

```
pip install -r requirements.txt
```

Additionally, since **`undetected-chromedriver` manages its own Chrome binary, you typically** ****do not** need to manually download a separate** `chromedriver` executable. It will automatically detect and manage your installed Chrome browser.

---

## Getting Started

### 1. Data Input

Place your Glibc CVE data in a file named **`dump-glibc.csv`** in the same directory as the script.

The script expects the following columns to be present in this CSV for processing:

| Column Name           | Description                                                                               | Example                  |
| --------------------- | ----------------------------------------------------------------------------------------- | ------------------------ |
| `CVE`               | The CVE identifier.                                                                       | `CVE-2021-3326`        |
| `P_COMMIT`          | The Git commit hash containing the patch.                                                 | `04a9e46a9a7a0862...`  |
| `FilePath`          | The specific file path of the change (optional but recommended for filtering).            | `sysdeps/posix/glob.c` |
| `Patched`           | A flag indicating if the vulnerability has a patch (script filters for `Patched != 0`). | `1`                    |
| `VULNERABILITY_URL` | A URL to a resource with more details on the vulnerability (optional).                    | `https://...`          |

### 2. Execution

Run the script from your terminal:

**Bash**

```
python extract_patches.py
```

The script will:

1. Read the CSV file.
2. Set up the undetected Chrome browser.
3. Iterate through each patched CVE.
4. Navigate to the commit diff URL (`https://sourceware.org/git/?p=glibc.git;a=commitdiff;h=...`).
5. Extract the code snippets.
6. Save the final results to `patched_dataset.csv`.

---

## Output Structure

The output file,  **`patched_dataset.csv`** , will contain a row for every file change extracted from a single CVE's patch commit.

| Column Name           | Description                                                                                                               |
| --------------------- | ------------------------------------------------------------------------------------------------------------------------- |
| `cve_id`            | The CVE identifier.                                                                                                       |
| `file_path`         | The path of the file that was modified.                                                                                   |
| `vulnerable_code`   | Code snippet corresponding to the removed lines (`-`) and context (`<span class="Apple-converted-space"> </span> `). |
| `patched_code`      | Code snippet corresponding to the added lines (`+`) and context (`<span class="Apple-converted-space"> </span> `).   |
| `patch_url`         | The URL of the commit diff page on sourceware.org.                                                                        |
| `commit_hash`       | The Git commit hash of the patch.                                                                                         |
| `vulnerability_url` | The original vulnerability URL from the input CSV.                                                                        |

---

## Configuration & Customization

You can modify the following constants within the script:

| Constant         | Default Value             | Description                      |
| ---------------- | ------------------------- | -------------------------------- |
| `CSV_FILENAME` | `"dump-glibc.csv"`      | The name of the input CSV file.  |
| `OUTPUT_FILE`  | `"patched_dataset.csv"` | The name of the output CSV file. |

**Important Note on Delays:** The script includes a `time.sleep(2)` delay between processing each CVE to be respectful of the target server's load and to further reduce the risk of triggering bot detection or being rate-limited. You may adjust this value if necessary.

---

## Troubleshooting

* **`FileNotFoundError: CSV file not found`** : Ensure `dump-glibc.csv` is in the same directory as the script.
* **`Bot detection still active`** :
* Try increasing the **`time.sleep(5)` within** `extract_code_from_commit_selenium`.
* Check your Chrome version is compatible with `undetected-chromedriver`.
* **`No code extracted`** : The structure of the sourceware.org page may have changed. You may need to inspect the HTML and update the `b` **and** `extract_code_from_patch_section` functions to target the new classes/elements.
