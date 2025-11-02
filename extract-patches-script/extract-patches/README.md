
# CVE Patch Extractor for Glibc Vulnerabilities

This Python script, `extract_patches.py`, leverages **GitPython** to directly interact with the official `glibc` Git repository. Its primary function is to extract the **full file contents,** both the **vulnerable** and **patched** versions, for all `.c` files modified within a security-related Git commit.

This approach provides a complete code-context dataset for training models or performing in-depth analysis, eliminating the need for complex web scraping or parsing of patch files.

## Key Features

* **Direct Git Integration:** Uses `gitpython` to clone and query the official `glibc` repository (`https://github.com/bminor/glibc.git`).
* **Commit Deduplication:** Processes each unique patch commit (`P_COMMIT`) only once, regardless of how many CVEs reference it.
* **Full File Extraction:** Extracts the complete file content (the entire source file) for the parent commit (vulnerable state) and the patch commit (patched state).
* **Comprehensive .c File Coverage:** Extracts and aggregates code changes from **ALL** `.c` files associated with a single security commit.
* **Structured Output:** Generates a clean CSV file (`patched_dataset.csv`) mapping CVEs to their corresponding full vulnerable and patched code files.

## Requirements

To run this script, you must have **Git** installed on your system. The following Python packages are also required:

```bash
pip install pandas gitpython
```

## Usage

### 1. Setup

Clone the repository containing the script and navigate into its directory:

```
git clone https://github.com/AI-SSD/ai-ssd-patch-generation-and-validation/tree/main/extract-patches-script
cd extract-patches-script
```

### 2. Data Preparation

Place your input CSV file, which contains the mapping of CVEs to their patch commits, in the same directory as the script. 

The script expects the input file to be named:

* **`dump-glibc.csv`** or setup the file name on **`CSV_FILENAME`.**

The CSV must contain, at a minimum, the following two columns:

1. **`CVE`** : The CVE identifier (e.g., `CVE-2019-1010002`).
2. **`P_COMMIT`** : The Git hash of the commit that contains the fix.

### 3. Execution

Run the script from your terminal:

```
python extract_patches.py
```

* **First Run:** The script will automatically clone the large **`glibc` Git repository into a local directory named** **`glibc_repo`** . This may take several minutes.
* **Subsequent Runs:** The script will open the existing local repository and perform a fast `git fetch` to ensure it is up-to-date.

### 4. Output

Upon completion, a new file will be generated in the script directory:

* **`patched_dataset.csv`**

This file contains the final dataset with the following columns:

| Column       | Description                                                                                   |
| ------------ | --------------------------------------------------------------------------------------------- |
| `CVE`      | The CVE ID.                                                                                   |
| `P_COMMIT` | The Git hash of the patch commit.                                                             |
| `FilePath` | The path to the modified `.c` file.                                                         |
| `V_CODE`   | The**full** content of the file **before** the patch commit (vulnerable version). |
| `P_CODE`   | The**full** content of the file **after** the patch commit (patched version).     |

Exportar para Sheets

## Configuration

You can easily adjust the script's configuration variables at the top of the file:

| Variable           | Default Value                             | Description                                                    |
| ------------------ | ----------------------------------------- | -------------------------------------------------------------- |
| `CSV_FILENAME`   | `"dump-glibc.csv"` or other             | The name of the input CSV file.                                |
| `OUTPUT_FILE`    | `"patched_dataset.csv"`                 | The name of the output CSV file.                               |
| `GLIBC_REPO_URL` | `"https://github.com/bminor/glibc.git"` | The Git URL for the glibc repository.                          |
| `REPO_CACHE_DIR` | `"glibc_repo"`                          | The local directory where the glibc repository will be cloned. |

Exportar para Sheets

## Notes on Repository Cloning

The repositories can sometimes be quite large. The initial clone process will consume significant disk space and may take time, depending on your network connection. This is a one-time operation, and the script handles updates efficiently afterward.
