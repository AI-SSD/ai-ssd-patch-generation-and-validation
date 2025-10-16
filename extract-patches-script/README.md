# CVE Patch Extractor for Glibc Vulnerabilities (Git-based)

This Python script is designed to build a dataset of vulnerable and patched code by directly interacting with the **Glibc Git repository** using the `gitpython` library. It processes a local CSV file containing Glibc vulnerability information, identifies relevant patch commits, and extracts the **full file content** before (vulnerable) and after (patched) each patch commit for all affected `.c` files.

Unlike methods relying on web scraping, this approach provides a direct, efficient, and reliable way to access the exact state of the source code.

## Key Features

* **Git-Native Extraction:** Uses `gitpython` to interact with a locally cloned repository, eliminating the need for web scraping or relying on external API rate limits.
* **Commit Deduplication:** Each unique patch commit (`P_COMMIT`) is processed only once, regardless of how many CVEs it fixes.
* **Comprehensive File Extraction:** Extracts the complete source code for **ALL** modified `.c` files within a single patch commit.
* **Full Code Context:** Stores the **FULL** vulnerable code and the **FULL** patched code for each affected file, providing complete context for analysis.
* **Local Caching:** Clones the Glibc repository once to a local directory (`./glibc_repo`) and reuses it for subsequent runs, speeding up the process.

## Requirements

The script is written in Python and requires the following libraries:

1. **pandas**: For reading and processing the input CSV data.
2. **gitpython**: For interacting with the Git repository.

### Installation

You can install the required dependencies using `pip`:

```bash
pip install pandas gitpython
```

## Setup and Usage

### 1. Prepare the Input Data

The script requires a CSV file containing Glibc vulnerability metadata.

* **File Name:** The expected input file must be named ****`dump-glibc.csv`** (as configured in** `CSV_FILENAME`).
* **Location:** Place the CSV file in the same directory as the script.
* **Required Columns:** The CSV must contain at least the following columns:
  * `CVE`: The CVE identifier (e.g., `CVE-2023-XXXX`).
  * `P_COMMIT`: The Git commit hash corresponding to the patch.
  * `Patched`: A numerical column where **`0` indicates no patch and any other value (`1`,** `2`, etc.) indicates a patch.

### 2. Run the Script

Execute the Python script directly:

```
python your_script_name.py
```

### Execution Steps

1. **Load CSV:** The script reads **`dump-glibc.csv` and filters for rows where** `Patched != 0`.
2. **Group Commits:** It aggregates CVEs by their unique `P_COMMIT` hash.
3. **Repository Setup:** It clones the Glibc repository from **`https://github.com/bminor/glibc.git` into the** `./glibc_repo` directory. If the directory exists, it attempts to open the existing repository and fetch the latest changes.
4. **Extraction:** It iterates through each unique commit, identifies all modified **`.c` files, and extracts the full source code content of the file from the** ****parent commit** (`V_CODE`) and the** **current commit** (`P_CODE`).
5. **Data Aggregation:** The results are combined, linking each file change back to all associated CVEs for that commit.

---

## Output

The final dataset is saved as a new CSV file named **`patched_dataset.csv`** in the same directory.

### Output File: `patched_dataset.csv`

| Column Name  | Description                                                                          | Example Value                                  |
| ------------ | ------------------------------------------------------------------------------------ | ---------------------------------------------- |
| `CVE`      | The vulnerability identifier.                                                        | `CVE-2021-3595`                              |
| `P_COMMIT` | The hash of the patch commit.                                                        | `23e7f4c568f54c9`                            |
| `FilePath` | The path to the affected `.c` file.                                                | `sysdeps/unix/sysv/linux/powerpc/getdents.c` |
| `V_CODE`   | The**FULL** source code of the file *before* the patch (vulnerable version). | `(long string of code)`                      |
| `P_CODE`   | The**FULL** source code of the file *after* the patch (patched version).     | `(long string of code)`                      |

---

## Troubleshooting

* **`FileNotFoundError: CSV file not found`** : Ensure `dump-glibc.csv` is in the same directory as the script.
* **Cloning takes too long** : The initial clone of the Glibc repository is large and can take several minutes. Subsequent runs will be much faster as the repository is cached in `./glibc_repo`.
* **Commit not found** : If a `P_COMMIT` is not found, the script will print an error message. This usually means the commit hash in the input CSV is incorrect or belongs to a branch/repository not tracked by the main Glibc repository.
* **`gitpython.exc.GitCommandError`** : Ensure you have Git installed and accessible in your system's PATH.

---
