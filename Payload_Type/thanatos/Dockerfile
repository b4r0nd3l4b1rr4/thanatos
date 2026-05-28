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
    nasm \
    yasm \
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

# Build UASM (MASM-compatible assembler for Linux)
RUN cd /tmp \
 && git clone --depth 1 https://github.com/Terraspace/UASM.git \
 && cd UASM \
 && sed -i 's/CC = clang-3.8/CC = gcc/' Makefile_Linux \
 && sed -i 's/-fwritable-strings//' Makefile_Linux \
 && sed -i 's/-ansi//' Makefile_Linux \
 && echo '/* stub */' > H/direct.h \
 && echo '/* stub */' > H/io.h \
 && sed -i '1i #ifndef _MAX_PATH\n#define _MAX_PATH 260\n#endif\n#define _pgmptr "uasm"\n#define _getcwd getcwd' dbgcv.c \
 && sed -i 's/(s - cv\.ps - 2)/((int)((char*)s - (char*)cv.ps) - 2)/' dbgcv.c \
 && sed -i 's/(s - start)/((int)((char*)s - (char*)start))/' dbgcv.c \
 && make -f Makefile_Linux -j$(nproc) \
 && cp GccUnixR/uasm /usr/local/bin/uasm \
 && chmod +x /usr/local/bin/uasm \
 && rm -rf /tmp/UASM

# Fetch and vendor all dependencies
RUN mkdir -p /vendor /opt/kudaes \
 && git clone --depth 1 https://github.com/Kudaes/Shelter /opt/kudaes/Shelter \
 && git clone --depth 1 https://github.com/Kudaes/Unwinder /opt/kudaes/Unwinder \
 && git clone --depth 1 https://github.com/Kudaes/MFTool /opt/kudaes/MFTool \
 && git clone --depth 1 https://github.com/Kudaes/Puzzle /opt/kudaes/Puzzle \
 && git clone --depth 1 https://github.com/Kudaes/Eclipse /opt/kudaes/Eclipse \
 && sed -i 's/dinvoke_rs = "=0.2.2"/dinvoke_rs = "=0.2.0"/' /opt/kudaes/Puzzle/SyncProvider/provider/Cargo.toml \
 && sed -i 's/name = "data"/name = "mftool_data"/' /opt/kudaes/MFTool/data/Cargo.toml \
 && sed -i 's|data = { path = "../data" }|data = { path = "../data", package = "mftool_data" }|' /opt/kudaes/MFTool/parser/Cargo.toml \
 && sed -i 's|data = { path = "../data" }|data = { path = "../data", package = "mftool_data" }|' /opt/kudaes/MFTool/utils/Cargo.toml \
 && sed -i 's|unwinder = "=0.1.4"|unwinder = { path = "/opt/kudaes/Unwinder/unwinder" }|' /opt/kudaes/Shelter/Cargo.toml \
 && cd /opt/kudaes/Unwinder/unwinder \
 && printf 'fn main() {\n    let out_dir = std::env::var("OUT_DIR").unwrap();\n    let target_env = std::env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();\n    if target_env == "gnu" {\n        let status = std::process::Command::new("uasm")\n            .args(&["-win64", "-Fo"])\n            .arg(format!("{}/gateway.o", out_dir))\n            .arg("src/gateway.asm")\n            .status().expect("uasm failed - install uasm");\n        if !status.success() { panic!("uasm failed to assemble gateway.asm"); }\n        let status = std::process::Command::new("x86_64-w64-mingw32-ar")\n            .args(&["crs"])\n            .arg(format!("{}/libgateway.a", out_dir))\n            .arg(format!("{}/gateway.o", out_dir))\n            .status().expect("ar failed");\n        if !status.success() { panic!("ar failed to create libgateway.a"); }\n        println!("cargo:rustc-link-search=native={}", out_dir);\n        println!("cargo:rustc-link-lib=static=gateway");\n    } else {\n        cc::Build::new().file("src/gateway.asm").compile("gateway");\n    }\n}\n' > build.rs \
 && cd /Mythic/thanatos/agent_code \
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
