### Corrected Dockerfile for Thanatos payload

# Note: Invoke this Dockerfile from the `Payload_Type/thanatos` directory using:
#   docker build -t docker.io/mehrn00/thanatos:v0.1.17 -f .docker/Dockerfile .

FROM docker.io/library/fedora:39

# Version of sccache to install
ENV SCCACHE_VERSION v0.7.6

# Install build dependencies
RUN dnf install -y \
    python3.11 \
    python3-pip \
    python3.11-devel \
    mingw64-gcc \
    mingw32-gcc \
    mingw64-gcc-c++ \
    mingw32-gcc-c++ \
    mingw64-winpthreads-static.noarch \
    mingw32-winpthreads-static.noarch \
    libgcc.i686 \
    libatomic-static.i686 \
    libatomic.i686 \
    glibc-devel.i686 \
    openssl-devel \
    openssl-devel.i686 \
    perl-FindBin \
    perl-File-Compare \
    perl-IPC-Cmd \
    perl-File-Copy \
    perl-lib \
    perl-core \
    perl-Time-Piece \
    clang \
    curl \
    git \
    make \
    musl-gcc \
    musl-libc-static \
    && dnf clean all


RUN python3.11 -m ensurepip

WORKDIR /tmp

# Install Python dependencies for Mythic container integration
COPY requirements.txt .
RUN python3.11 -m pip install -r requirements.txt
RUN rm requirements.txt

# Install Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs -o rustup.sh \
    && sh rustup.sh -y \
    --profile minimal \
    --default-toolchain stable \
    -t x86_64-unknown-linux-gnu \
    -t i686-unknown-linux-gnu \
    -t x86_64-unknown-linux-musl \
    -t x86_64-pc-windows-gnu \
    -t i686-pc-windows-gnu

RUN rm -f rustup.sh

ENV PATH=$PATH:/root/.cargo/bin

# Install sccache for caching Rust builds
RUN curl -L \
    "https://github.com/mozilla/sccache/releases/download/${SCCACHE_VERSION}/sccache-${SCCACHE_VERSION}-x86_64-unknown-linux-musl.tar.gz" \
    -o sccache-${SCCACHE_VERSION}-x86_64-unknown-linux-musl.tar.gz
RUN tar xf sccache-${SCCACHE_VERSION}-x86_64-unknown-linux-musl.tar.gz
RUN mv sccache-${SCCACHE_VERSION}-x86_64-unknown-linux-musl/sccache /usr/bin/sccache
RUN chmod +x /usr/bin/sccache
RUN rm -rf sccache-${SCCACHE_VERSION}-x86_64-unknown-linux-musl
RUN rm -f sccache-${SCCACHE_VERSION}-x86_64-unknown-linux-musl.tar.gz

# Copy Mythic payload framework
WORKDIR /Mythic
COPY main.py main.py
COPY thanatos thanatos

WORKDIR /Mythic/thanatos/agent_code

# Fetch and vendor all dependencies
RUN mkdir -p /vendor /opt/kudaes \
 && git clone --depth 1 https://github.com/Kudaes/Shelter /opt/kudaes/Shelter \
 && git clone --depth 1 https://github.com/Kudaes/MFTool /opt/kudaes/MFTool \
 && git clone --depth 1 https://github.com/Kudaes/Puzzle /opt/kudaes/Puzzle \
 && git clone --depth 1 https://github.com/Kudaes/Eclipse /opt/kudaes/Eclipse \
 && echo '[build]' > /root/.cargo/config.toml \
 && echo 'rustc-wrapper = "/usr/bin/sccache"' >> /root/.cargo/config.toml \
 && cargo fetch \
 && cargo vendor /vendor \
 && echo '[build]' > /root/.cargo/config.toml \
 && echo 'rustc-wrapper = "/usr/bin/sccache"' >> /root/.cargo/config.toml \
 && echo '[source.crates-io]' >> /root/.cargo/config.toml \
 && echo 'replace-with = "vendored-sources"' >> /root/.cargo/config.toml \
 && echo '[source.vendored-sources]' >> /root/.cargo/config.toml \
 && echo 'directory = "/vendor"' >> /root/.cargo/config.toml

WORKDIR /Mythic

# Configure sccache
ENV SCCACHE_DIR /Mythic/.cache/sccache

CMD ["python3.11", "main.py"]
