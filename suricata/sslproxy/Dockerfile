# ==============================================================================
# STAGE 1: Build Environment
# ==============================================================================
FROM debian:trixie-slim AS builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    build-essential \
    libssl-dev \
    libevent-dev \
    libpcap-dev \
    libsqlite3-dev \
    libnet1-dev \
    git \
    && rm -rf /var/lib/apt/lists/*

# Clone SSLproxy, patch limits in protossl.c, compile, and strip binary
RUN GIT_SSL_NO_VERIFY=true git clone https://github.com/sonertari/SSLproxy.git /opt/sslproxy \
    && cd /opt/sslproxy \
    && sed -i 's/#define MAX_CN_LEN 4096/#define MAX_CN_LEN 65536/g' src/protossl.c \
    && sed -i 's/#define MAX_CN_TOKENS 100/#define MAX_CN_TOKENS 2048/g' src/protossl.c \
    && make -j$(nproc) \
    && strip src/sslproxy

# ==============================================================================
# STAGE 2: Minimal Runtime Environment
# ==============================================================================
FROM debian:trixie-slim

ENV DEBIAN_FRONTEND=noninteractive

# Install all libevent runtime modules, core libraries, and python
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
    iptables \
    iproute2 \
    python3 \
    python3-scapy \
    python3-pip \
    && curl -kLo /usr/local/share/ca-certificates/mozilla-ca.crt https://curl.se/ca/cacert.pem \
    && update-ca-certificates --fresh \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Copy compiled binary from builder stage
COPY --from=builder /opt/sslproxy/src/sslproxy /usr/bin/sslproxy
RUN chmod +x /usr/bin/sslproxy

# Copy configuration and entrypoint
COPY sslproxy.conf /etc/sslproxy/sslproxy.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
