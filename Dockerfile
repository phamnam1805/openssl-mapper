FROM debian:trixie

ARG OPENSSL_VERSION=3.6.2

# ── System packages ──────────────────────────────────────────────────────────
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        # Build tools for OpenSSL
        git \
        perl \
        gcc \
        make \
        libc6-dev \
        zlib1g-dev \
        dh-autoreconf \
        ca-certificates \
        # Python
        python3 \
        python3-pip \
        python3-venv \
        # Debugging and tracing tools
        strace \
        gdb \
        # Utilities
        vim \
        less \
        rlwrap \
        net-tools \
        iproute2 \
        procps \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# ── Build OpenSSL from source ─────────────────────────────────────────────────
RUN git clone --depth 1 --branch openssl-${OPENSSL_VERSION} \
        https://github.com/openssl/openssl.git /tmp/openssl-src && \
    cd /tmp/openssl-src && \
    ./Configure --prefix=/usr/local/openssl --openssldir=/usr/local/openssl \
        shared zlib && \
    make -j"$(nproc)" && \
    make install_sw && \
    echo /usr/local/openssl/lib64 > /etc/ld.so.conf.d/openssl.conf && \
    ldconfig && \
    rm -rf /tmp/openssl-src

ENV PATH="/usr/local/openssl/bin:${PATH}"
ENV LD_LIBRARY_PATH="/usr/local/openssl/lib64:${LD_LIBRARY_PATH}"

# ── Clone pylstar-tls variants ────────────────────────────────────────────────
RUN mkdir -p /inference-tools

# oob-handler branch (latest)
RUN git clone --branch oob-handler \
        https://gitlab.com/phamnam1805/pylstar-tls.git \
        /inference-tools/oob-pylstar-tls

# original-pylstar-tls pinned to specific commit
RUN git clone https://gitlab.com/phamnam1805/pylstar-tls.git \
        /inference-tools/original-pylstar-tls && \
    git -C /inference-tools/original-pylstar-tls checkout \
        2554ceb702db9892d2364398d0c20333cae8b527

# ── Python virtual environment ────────────────────────────────────────────────
RUN python3 -m venv /inference-tools/venv

RUN /inference-tools/venv/bin/pip install --upgrade pip && \
    /inference-tools/venv/bin/pip install \
        -r /inference-tools/oob-pylstar-tls/requirements.txt

ENV PATH="/inference-tools/venv/bin:${PATH}"
ENV VIRTUAL_ENV="/inference-tools/venv"

# ── Working directory ─────────────────────────────────────────────────────────
RUN mkdir -p /project
WORKDIR /project
