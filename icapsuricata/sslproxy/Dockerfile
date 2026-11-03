# ==============================================================================
# STAGE 1: Build Environment
# ==============================================================================
FROM debian:trixie-slim AS builder

ENV DEBIAN_FRONTEND=noninteractive
ENV PKG_CONFIG_PATH=/usr/local/lib/pkgconfig
ENV LD_LIBRARY_PATH=/usr/local/lib

ARG NGHTTP3_VERSION=1.19.0
ARG NGTCP2_VERSION=1.26.0

# Build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    build-essential \
    clang-19 \
    autoconf \
    automake \
    autotools-dev \
    libtool \
    pkgconf \
    libssl-dev \
    libevent-dev \
    libpcap-dev \
    libsqlite3-dev \
    libnet1-dev \
    libnghttp2-dev \
    git \
    && rm -rf /var/lib/apt/lists/*


# ==============================================================================
# BUILD NGHTTP3
# ==============================================================================

RUN set -eux; \
    git clone --depth 1 \
        --branch "v${NGHTTP3_VERSION}" \
        https://github.com/ngtcp2/nghttp3.git \
        /tmp/nghttp3; \
    cd /tmp/nghttp3; \
    git submodule update --init --depth 1; \
    autoreconf -fi; \
    CC=clang-19 ./configure \
        --prefix=/usr/local \
        --libdir=/usr/local/lib \
        --enable-lib-only; \
    make -j"$(nproc)"; \
    make install; \
    ldconfig; \
    pkg-config --atleast-version=1.12.0 libnghttp3; \
    pkg-config --modversion libnghttp3; \
    grep -q 'nghttp3_tstamp' \
        /usr/local/include/nghttp3/nghttp3.h; \
    grep -q 'nghttp3_conn_read_stream2' \
        /usr/local/include/nghttp3/nghttp3.h


# ==============================================================================
# BUILD NGTCP2 WITH OPENSSL SUPPORT
# ==============================================================================

RUN set -eux; \
    git clone --depth 1 \
        --branch "v${NGTCP2_VERSION}" \
        https://github.com/ngtcp2/ngtcp2.git \
        /tmp/ngtcp2; \
    cd /tmp/ngtcp2; \
    git submodule update --init --depth 1; \
    autoreconf -fi; \
    ./configure \
        --prefix=/usr/local \
        --libdir=/usr/local/lib \
        --enable-lib-only \
        --with-openssl; \
    make -j"$(nproc)"; \
    make install; \
    ldconfig; \
    pkg-config --atleast-version=1.24.0 libngtcp2; \
    pkg-config --modversion libngtcp2; \
    pkg-config --modversion libngtcp2_crypto_ossl; \
    grep -q 'recv_stop_sending' \
        /usr/local/include/ngtcp2/ngtcp2.h


# ==============================================================================
# BUILD SSLPROXY
# ==============================================================================

RUN set -eux; \
    GIT_SSL_NO_VERIFY=true git clone --depth 1 \
        --branch master \
        https://github.com/sonertari/SSLproxy.git \
        /opt/sslproxy; \
    cd /opt/sslproxy; \
    \
    # Preserve certificate parsing limits.
    sed -i \
        's/#define MAX_CN_LEN 4096/#define MAX_CN_LEN 65536/g' \
        src/protossl.c; \
    sed -i \
        's/#define MAX_CN_TOKENS 100/#define MAX_CN_TOKENS 2048/g' \
        src/protossl.c; \
    \
    # Enable HTTP/3 compilation.
    find . -type f \
        \( -name '*Makefile*' -o -name 'GNUmakefile*' -o -name '*.mk' \) \
        -exec sed -i 's/-DWITHOUT_HTTP3//g' {} +; \
    \
    # Ensure HTTP/3 is not disabled.
    if grep -RIn \
        --include='*Makefile*' \
        --include='GNUmakefile*' \
        --include='*.mk' \
        -- '-DWITHOUT_HTTP3' .; then \
        echo "ERROR: WITHOUT_HTTP3 is still present"; \
        exit 1; \
    fi; \
    \
    # --------------------------------------------------------------------------
    # IMPORTANT:
    # Register the custom HTTP/3 libraries in SSLproxy's build dependencies.
    # --------------------------------------------------------------------------
    grep -q '^PKGS:=' Mk/main.mk; \
    sed -i \
        '/^PKGS:=/a PKGS+= libnghttp3 libngtcp2_crypto_ossl libngtcp2' \
        Mk/main.mk; \
    grep -q \
        '^PKGS+= libnghttp3 libngtcp2_crypto_ossl libngtcp2$' \
        Mk/main.mk; \
    \
    # --------------------------------------------------------------------------
    # Verify HTTP/3 development dependencies.
    # --------------------------------------------------------------------------
    pkg-config --exists \
        libnghttp3 \
        libngtcp2_crypto_ossl \
        libngtcp2; \
    \
    echo "HTTP/3 library versions:"; \
    pkg-config --modversion libnghttp3; \
    pkg-config --modversion libngtcp2; \
    pkg-config --modversion libngtcp2_crypto_ossl; \
    \
    echo "HTTP/3 linker flags:"; \
    pkg-config --libs \
        libnghttp3 \
        libngtcp2_crypto_ossl \
        libngtcp2; \
    \
    # --------------------------------------------------------------------------
    # Compile SSLproxy.
    # --------------------------------------------------------------------------
    make -j"$(nproc)"; \
    strip src/sslproxy; \
    \
    echo "SSLproxy build dependencies:"; \
    ldd src/sslproxy


# ==============================================================================
# STAGE 2: Minimal Runtime Environment
# ==============================================================================

FROM debian:trixie-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    openssl \
    libevent-2.1-7t64 \
    libevent-core-2.1-7t64 \
    libevent-extra-2.1-7t64 \
    libevent-openssl-2.1-7t64 \
    libevent-pthreads-2.1-7t64 \
    libpcap0.8t64 \
    libsqlite3-0 \
    libnet1 \
    libnghttp2-14 \
    iptables \
    iproute2 \
    python3 \
    python3-scapy \
    python3-pip \
    && curl -fsSLo \
        /usr/local/share/ca-certificates/mozilla-ca.crt \
        https://curl.se/ca/cacert.pem \
    && update-ca-certificates --fresh \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*


# ==============================================================================
# COPY CUSTOM HTTP/3 LIBRARIES
# ==============================================================================

COPY --from=builder /usr/local/lib/ /usr/local/lib/

ENV LD_LIBRARY_PATH=/usr/local/lib

RUN ldconfig


# ==============================================================================
# COPY SSLPROXY
# ==============================================================================

COPY --from=builder \
    /opt/sslproxy/src/sslproxy \
    /usr/bin/sslproxy

RUN chmod +x /usr/bin/sslproxy


# ==============================================================================
# COPY CONFIGURATION AND ENTRYPOINT
# ==============================================================================

COPY sslproxy.conf /etc/sslproxy/sslproxy.conf
COPY entrypoint.sh /entrypoint.sh

RUN chmod +x /entrypoint.sh


# ==============================================================================
# VERIFY RUNTIME LIBRARIES
# ==============================================================================

RUN set -eux; \
    ldconfig; \
    ldd /usr/bin/sslproxy; \
    if ldd /usr/bin/sslproxy | grep -q 'not found'; then \
        echo "ERROR: Missing runtime dependencies"; \
        exit 1; \
    fi

ENTRYPOINT ["/entrypoint.sh"]
