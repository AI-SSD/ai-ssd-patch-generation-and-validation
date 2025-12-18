#!/bin/bash
set -e

# Trap exit to ensure we report failure if something crashes early
finish() {
    local ret=$?
    if [ ! -f "/output/report_${CVE}.txt" ]; then
        echo "Script failed with exit code $ret"
        mkdir -p /output
        echo "CVE: $CVE" > "/output/report_${CVE}.txt"
        echo "STATUS: SCRIPT_CRASH" >> "/output/report_${CVE}.txt"
        echo "Exit Code: $ret" >> "/output/report_${CVE}.txt"
        echo "Output: Script crashed before generating a report." >> "/output/report_${CVE}.txt"
        
        # ADDED: Dump logs if they exist to help debug the crash
        if [ -f "configure.log" ]; then
            echo "--- configure.log (Tail) ---" >> "/output/report_${CVE}.txt"
            tail -n 20 configure.log >> "/output/report_${CVE}.txt"
        fi
        if [ -f "make.log" ]; then
            echo "--- make.log (Tail) ---" >> "/output/report_${CVE}.txt"
            tail -n 20 make.log >> "/output/report_${CVE}.txt"
        fi
    fi
}
trap finish EXIT
# -----------------------------------------------------------

echo "--------------------------------------------------"
echo "Running Test Script for $CVE"
echo "--------------------------------------------------"

# --- 1. PREPARATION ---
echo "[+] Applying patch..."
if [ -f "/input/patched.c" ]; then
    cp /input/patched.c "/root/glibc-test/glibc-source/$TARGET_FILE_PATH"
else
    echo "ERROR: /input/patched.c not found!"
    exit 1
fi

# --- 2. BUILD GLIBC ---
echo "[+] Building Glibc..."
cd /root/glibc-test/glibc-source

# Dependencies for old glibc
wget -q -O scripts/config.guess 'https://raw.githubusercontent.com/gcc-mirror/gcc/master/config.guess'
wget -q -O scripts/config.sub 'https://raw.githubusercontent.com/gcc-mirror/gcc/master/config.sub'
chmod +x scripts/config.guess scripts/config.sub

# Fixes for CVE-2012-3480 and CVE-2015-7547 (build compatibility)
[ -f "configure" ] && sed -i 's/ac_verc_fail=yes/ac_verc_fail=no/g' configure
[ -f "misc/regexp.c" ] && sed -i 's/^\(char \*loc[12s]\);/\1 = 0;/g' misc/regexp.c

mkdir -p build && cd build

# Compile Flags (Robust)
export CC="gcc -no-pie -fno-stack-protector -fcommon -U_FORTIFY_SOURCE"
export CXX="g++ -no-pie -fno-stack-protector -fcommon -U_FORTIFY_SOURCE"

set +e
../configure --prefix=/usr/local/glibc-test --disable-werror CFLAGS="-g -O2" > configure.log 2>&1
CONF_RET=$?
set -e

if [ $CONF_RET -ne 0 ]; then
    mkdir -p /output
    echo "CVE: $CVE" > "/output/report_${CVE}.txt"
    echo "STATUS: BUILD_FAILED (CONFIGURE)" >> "/output/report_${CVE}.txt"
    tail -n 50 configure.log >> "/output/report_${CVE}.txt"
    exit 1
fi

echo "    Compiling..."
set +e
make -j$(nproc) > make.log 2>&1
MAKE_RET=$?
set -e

if [ $MAKE_RET -ne 0 ]; then
    mkdir -p /output
    echo "CVE: $CVE" > "/output/report_${CVE}.txt"
    echo "STATUS: BUILD_FAILED (MAKE)" >> "/output/report_${CVE}.txt"
    tail -n 50 make.log >> "/output/report_${CVE}.txt"
    exit 1
fi

# --- 3. COMPILE EXPLOIT ---
echo "[+] Compiling Exploit..."
EXPLOIT_SRC="/root/glibc-test/exploits/${CVE}.c"
EXPLOIT_BIN="/root/glibc-test/exploits/${CVE}"

if [ ! -f "$EXPLOIT_SRC" ]; then
    # Try finding any .c file in the exploits dir if the exact name matches
    EXPLOIT_SRC=$(find /root/glibc-test/exploits -name "*.c" | head -n 1)
fi

if [ -f "$EXPLOIT_SRC" ]; then
    gcc "$EXPLOIT_SRC" -o "$EXPLOIT_BIN"
else
    echo "CVE: $CVE" > "/output/report_${CVE}.txt"
    echo "STATUS: EXPLOIT_MISSING" >> "/output/report_${CVE}.txt"
    exit 1
fi

# --- 4. RUN EXPLOIT ---
echo "[+] Running Exploit..."
BUILD_DIR="/root/glibc-test/glibc-source/build"
LOADER="$BUILD_DIR/elf/ld.so"

# Run with timeout (10 seconds) to prevent infinite loops
set +e
timeout 10s $LOADER --library-path $BUILD_DIR "$EXPLOIT_BIN" > result.txt 2>&1
EXIT_CODE=$?
set -e

# --- 5. REPORT GENERATION ---
mkdir -p /output
REPORT_FILE="/output/report_${CVE}.txt"
echo "CVE: $CVE" > "$REPORT_FILE"
echo "Target: $TARGET_FILE_PATH" >> "$REPORT_FILE"

# Interpret Exit Code
if [ $EXIT_CODE -eq 0 ]; then
    echo "STATUS: VULNERABLE (Exploit ran successfully)" >> "$REPORT_FILE"
elif [ $EXIT_CODE -eq 124 ]; then
    echo "STATUS: TIMEOUT (Exploit hung)" >> "$REPORT_FILE"
elif [ $EXIT_CODE -eq 139 ]; then
    echo "STATUS: PATCHED (Exploit Segfaulted)" >> "$REPORT_FILE"
else
    echo "STATUS: PATCHED (Exploit Failed with code $EXIT_CODE)" >> "$REPORT_FILE"
fi

echo "Raw Exit Code: $EXIT_CODE" >> "$REPORT_FILE"
echo "--- Output ---" >> "$REPORT_FILE"
cat result.txt >> "$REPORT_FILE"

echo "Done. Report saved."