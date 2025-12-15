#!/bin/bash
set -e

# Environment variables are expected to be set by Docker ENV
# GIT_COMMIT, CVE, TARGET_FILE_PATH

# Trap exit to ensure we report failure if something crashes early
finish() {
    local ret=$?
    # If report doesn't exist yet, create a failure report
    if [ ! -f "/output/report_${CVE}.txt" ]; then
        echo "Script failed with exit code $ret"
        mkdir -p /output
        echo "CVE: $CVE" > "/output/report_${CVE}.txt"
        echo "Exit Code: $ret (Script Failed)" >> "/output/report_${CVE}.txt"
        echo "Output: Script failed before exploit execution. Check container logs." >> "/output/report_${CVE}.txt"
    fi
}
trap finish EXIT

echo "--------------------------------------------------"
echo "Running Test Script"
echo "CVE: $CVE"
echo "Target File: $TARGET_FILE_PATH"
echo "--------------------------------------------------"

# 1. Move patched file
echo "[+] Applying patch..."
if [ -f "/input/patched.c" ]; then
    cp /input/patched.c "/root/glibc-test/glibc-source/$TARGET_FILE_PATH"
    echo "    Patched file copied to /root/glibc-test/glibc-source/$TARGET_FILE_PATH"
else
    echo "    ERROR: /input/patched.c not found!"
    
    mkdir -p /output
    echo "CVE: $CVE" > "/output/report_${CVE}.txt"
    echo "Exit Code: 1 (Patch File Missing)" >> "/output/report_${CVE}.txt"
    echo "Output: /input/patched.c not found." >> "/output/report_${CVE}.txt"

    exit 1
fi

# 2. Build Glibc
echo "[+] Building Glibc..."
cd /root/glibc-test/glibc-source

# Update config.guess and config.sub to support aarch64 (needed for older glibc on newer hardware)
echo "    Updating config.guess and config.sub..."
wget -q -O scripts/config.guess 'https://git.savannah.gnu.org/gitweb/?p=config.git;a=blob_plain;f=config.guess;hb=HEAD'
wget -q -O scripts/config.sub 'https://git.savannah.gnu.org/gitweb/?p=config.git;a=blob_plain;f=config.sub;hb=HEAD'
chmod +x scripts/config.guess scripts/config.sub

mkdir -p build
cd build

# Configure
echo "    Configuring..."
# We use --disable-werror because older glibc versions might have warnings with newer gcc
set +e
../configure --prefix=/usr/local/glibc-test --disable-werror > configure.log 2>&1
CONF_RET=$?
set -e
if [ $CONF_RET -ne 0 ]; then
    echo "    ERROR: Configure failed. See configure.log"
    cat configure.log
    
    mkdir -p /output
    echo "CVE: $CVE" > "/output/report_${CVE}.txt"
    echo "Exit Code: $CONF_RET (Configure Failed)" >> "/output/report_${CVE}.txt"
    echo "Output:" >> "/output/report_${CVE}.txt"
    cat configure.log >> "/output/report_${CVE}.txt"

    exit 1
fi

# Make
echo "    Compiling (make)... This may take a while."
set +e
make -j$(nproc) > make.log 2>&1
MAKE_RET=$?
set -e
if [ $MAKE_RET -ne 0 ]; then
    echo "    ERROR: Make failed. See make.log"
    tail -n 50 make.log

    mkdir -p /output
    echo "CVE: $CVE" > "/output/report_${CVE}.txt"
    echo "Exit Code: $MAKE_RET (Make Failed)" >> "/output/report_${CVE}.txt"
    echo "Output:" >> "/output/report_${CVE}.txt"
    tail -n 50 make.log >> "/output/report_${CVE}.txt"

    exit 1
fi
echo "    Glibc built successfully."

# 3. Compile Exploit
echo "[+] Compiling Exploit..."
EXPLOIT_SRC="/root/glibc-test/exploits/${CVE}.c"
EXPLOIT_BIN="/root/glibc-test/exploits/${CVE}"

if [ -f "$EXPLOIT_SRC" ]; then
    echo "    Found exploit source: $EXPLOIT_SRC"
    gcc "$EXPLOIT_SRC" -o "$EXPLOIT_BIN"
    if [ $? -ne 0 ]; then
        echo "    ERROR: Exploit compilation failed for $EXPLOIT_SRC"

        mkdir -p /output
        echo "CVE: $CVE" > "/output/report_${CVE}.txt"
        echo "Exit Code: 1 (Exploit Compilation Failed)" >> "/output/report_${CVE}.txt"
        echo "Output: GCC failed to compile exploit." >> "/output/report_${CVE}.txt"

        exit 1
    fi
    echo "    Exploit compiled to $EXPLOIT_BIN"
else
    echo "    ERROR: Exploit source $EXPLOIT_SRC not found."
    exit 1
fi

# 4. Run Exploit
echo "[+] Running Exploit..."
# We need to run the exploit using the NEW glibc.
# Using the dynamic linker from the build.
BUILD_DIR="/root/glibc-test/glibc-source/build"
LOADER="$BUILD_DIR/elf/ld.so"
LIBC_PATH="$BUILD_DIR"

# Verify loader exists
if [ ! -f "$LOADER" ]; then
    echo "    ERROR: Loader not found at $LOADER"

    mkdir -p /output
    echo "CVE: $CVE" > "/output/report_${CVE}.txt"
    echo "Exit Code: 1 (Loader Missing)" >> "/output/report_${CVE}.txt"
    echo "Output: Loader not found at $LOADER." >> "/output/report_${CVE}.txt"

    exit 1
fi

# Use absolute path to the exploit binary when invoking the loader
echo "    Executing: $LOADER --library-path $LIBC_PATH $EXPLOIT_BIN"
# Run the exploit and capture output
set +e # Allow failure of the exploit (it might crash or return non-zero)
$LOADER --library-path $LIBC_PATH "$EXPLOIT_BIN" > result.txt 2>&1
EXIT_CODE=$?
set -e

echo "    Exploit exit code: $EXIT_CODE"
echo "    Output:"
cat result.txt

# 5. Report
echo "[+] Generating Report..."
mkdir -p /output
REPORT_FILE="/output/report_${CVE}.txt"
echo "CVE: $CVE" > "$REPORT_FILE"
echo "Exit Code: $EXIT_CODE" >> "$REPORT_FILE"
echo "Output:" >> "$REPORT_FILE"
cat result.txt >> "$REPORT_FILE"

echo "Done. Report saved to $REPORT_FILE"
