# Install dependencies
# We install gcc-9 because older glibc versions (like 2.15 or 2.20) are often incompatible with newer GCC (11+)
# Ubuntu 22.04 comes with GCC 11 by default. We need to add older repositories or use a different base image.
# However, for simplicity, we can try to install gcc-9 or gcc-10 if available, or use an older base image.
# Switching to ubuntu:20.04 which has gcc-9 by default might be safer for these older glibc versions.
FROM ubuntu:20.04

# Define build arguments
ARG GIT_COMMIT
ARG CVE
ARG MODEL
ARG TARGET_FILE_PATH

# Persist args as ENV for the script
ENV GIT_COMMIT=${GIT_COMMIT}
ENV CVE=${CVE}
ENV MODEL=${MODEL}
ENV TARGET_FILE_PATH=${TARGET_FILE_PATH}
ENV DEBIAN_FRONTEND=noninteractive

# Install dependencies
RUN apt-get update && apt-get install -y \
    build-essential gawk bison python3 texinfo gettext wget git nano \
    netcat-openbsd gcc-9 g++-9 \
    && rm -rf /var/lib/apt/lists/*

# Set gcc-9 as default
RUN update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-9 100 \
    && update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-9 100

# Create working directories
RUN mkdir -p /root/glibc-test /root/glibc-test/patches /input /output
WORKDIR /root/glibc-test

# Clone glibc source code
RUN git clone https://github.com/bminor/glibc.git glibc-source
WORKDIR /root/glibc-test/glibc-source

# Checkout specific commit
RUN git checkout ${GIT_COMMIT}

# Copy patched file to input directory (staging area)
COPY patched.c /input/patched.c

# Copy specific exploit file
COPY exploits/ /root/glibc-test/exploits/

# Copy the test runner script
COPY run_test.sh /root/glibc-test/run_test.sh
RUN chmod +x /root/glibc-test/run_test.sh

WORKDIR /root/glibc-test

# Set the entrypoint to the script
CMD ["/root/glibc-test/run_test.sh"]
