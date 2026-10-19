# ==============================================================================
# STAGE 1: BUILDER
# Build Suricata, patched c-icap, and icapsuricata
# ==============================================================================
FROM debian:trixie-slim AS builder

ENV DEBIAN_FRONTEND=noninteractive

# ------------------------------------------------------------------------------
# 1. Build dependencies
# ------------------------------------------------------------------------------
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    git \
    autoconf \
    automake \
    libtool \
    cbindgen \
    libpcap-dev \
    libnet1-dev \
    libyaml-dev \
    zlib1g-dev \
    libbz2-dev \
    libbrotli-dev \
    libzstd-dev \
    libcap-ng-dev \
    libssl-dev \
    libmagic-dev \
    libjansson-dev \
    libpcre2-dev \
    pkg-config \
    make \
    cargo \
    rustc \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*


# ------------------------------------------------------------------------------
# 2. Build Suricata 8.0.7 as a shared library
# ------------------------------------------------------------------------------
WORKDIR /tmp

RUN git clone --depth 1 --branch suricata-8.0.7 \
    https://github.com/OISF/suricata.git

WORKDIR /tmp/suricata

RUN ./autogen.sh && \
    ./configure \
        --disable-gccmarch-native \
        --sysconfdir=/etc && \
    make -j"$(nproc)" && \
    make install install-headers install-library && \
    ldconfig && \
    command -v libsuricata-config && \
    test -f /usr/local/lib/libsuricata.so

# ------------------------------------------------------------------------------
# 3. Install Suricata's auxiliary configuration files
# ------------------------------------------------------------------------------
# These files are required by the paths in suricata.yaml.
# Install them into /etc/suricata so they are copied into the runtime stage.

RUN set -eux; \
    install -D -m 0644 \
        /tmp/suricata/etc/classification.config \
        /etc/suricata/classification.config; \
    install -D -m 0644 \
        /tmp/suricata/etc/reference.config \
        /etc/suricata/reference.config; \
    install -D -m 0644 \
        /tmp/suricata/threshold.config \
        /etc/suricata/threshold.config; \
    test -s /etc/suricata/classification.config; \
    test -s /etc/suricata/reference.config; \
    test -s /etc/suricata/threshold.config


# ------------------------------------------------------------------------------
# 4. Build patched c-icap
# ------------------------------------------------------------------------------
WORKDIR /tmp

RUN git clone --depth 1 \
    https://github.com/c-icap/c-icap-server.git

WORKDIR /tmp/c-icap-server

# icapsuricata requires service_data in ci_connection_t.
# Patch the source BEFORE compiling the server and its API library.
RUN set -eux; \
    sh RECONF; \
    if ! grep -Fq 'void *service_data;' include/net_io.h; then \
        grep -q 'int32_t flags;' include/net_io.h; \
        sed -i \
            '/^[[:space:]]*int32_t flags;[[:space:]]*$/a\    void *service_data;' \
            include/net_io.h; \
    fi; \
    grep -Fq 'void *service_data;' include/net_io.h; \
    ./configure \
        --prefix=/usr/local \
        --sysconfdir=/etc/c-icap \
        --libdir=/usr/local/lib; \
    make -j"$(nproc)"; \
    make install; \
    ldconfig


# ------------------------------------------------------------------------------
# 5. Build icapsuricata
# ------------------------------------------------------------------------------
WORKDIR /tmp

RUN git clone --depth 1 \
    https://github.com/sonertari/icapsuricata.git

WORKDIR /tmp/icapsuricata

# Adapt the module to the c-icap API and service loader.
RUN set -eux; \
    sed -i \
        -e 's/ci_icap_request_get_header(req, /ci_headers_value(req->request_header, /g' \
        -e 's/static ci_service_module_t suricata_service = {/ci_service_module_t service = {/' \
        -e '/_CI_DECLARE_SERVICE(suricata_service);/d' \
        srv_suricata.c; \
    ! grep -q 'ci_icap_request_get_header' srv_suricata.c; \
    ! grep -q '_CI_DECLARE_SERVICE(suricata_service)' srv_suricata.c; \
    make CICAP_PREFIX=/usr/local

RUN set -eux; \
    install -D -m 0755 \
        srv_suricata.so \
        /usr/local/lib/c_icap/srv_suricata.so; \
    ldconfig


# ------------------------------------------------------------------------------
# 6. Configure c-icap
# ------------------------------------------------------------------------------
RUN set -eux; \
    CONF=/etc/c-icap/c-icap.conf; \
    test -f "$CONF"; \
    set_directive() { \
        key="$1"; \
        value="$2"; \
        if grep -qE "^[[:space:]]*${key}[[:space:]]+" "$CONF"; then \
            sed -i -E \
                "s|^[[:space:]]*${key}[[:space:]]+.*|${key} ${value}|" \
                "$CONF"; \
        else \
            printf '\n%s %s\n' "$key" "$value" >> "$CONF"; \
        fi; \
    }; \
    set_directive Port 1344; \
    set_directive ModulesDir /usr/local/lib/c_icap; \
    set_directive ServicesDir /usr/local/lib/c_icap; \
    set_directive User c-icap; \
    set_directive Group c-icap; \
    set_directive PidFile /var/run/c-icap/c-icap.pid; \
    set_directive CommandsSocket /var/run/c-icap/c-icap.ctl; \
    set_directive ServerLog /var/log/c-icap/server.log; \
    set_directive StartServers 1; \
    set_directive MaxServers 1; \
    set_directive MinSpareThreads 4; \
    set_directive MaxSpareThreads 16; \
    set_directive ThreadsPerChild 16; \
    printf '\n\
# Suricata ICAP service\n\
Service suricata_service srv_suricata.so\n\
suricata.Preview 1024\n\
suricata.BufSize 4096\n\
' >> "$CONF"; \
    mkdir -p \
        /etc/suricata \
        /etc/icapsuricata \
        /var/lib/suricata \
        /var/log/suricata \
        /var/log/c-icap \
        /var/run/c-icap


# ------------------------------------------------------------------------------
# 7. Automatically determine the runtime Debian packages
# ------------------------------------------------------------------------------
# Source trees and compilation tools will not be included in the
# runtime image. Determine which Debian packages provide the external
# shared libraries required by the compiled software.

RUN set -eux; \
    ldconfig; \
    : > /tmp/runtime-library-paths.txt; \
    for target in \
        /usr/local/bin/c-icap \
        /usr/local/lib/libsuricata.so \
        /usr/local/lib/c_icap/srv_suricata.so; \
    do \
        echo "Inspecting runtime dependencies of $target"; \
        output="$(ldd "$target" 2>&1 || true)"; \
        printf '%s\n' "$output"; \
        if printf '%s\n' "$output" | grep -q 'not found'; then \
            echo "ERROR: An external dependency is missing in the builder"; \
            exit 1; \
        fi; \
        printf '%s\n' "$output" | \
            awk '/=> \// {print $3} /^\// {print $1}' \
            >> /tmp/runtime-library-paths.txt; \
    done; \
    sort -u -o /tmp/runtime-library-paths.txt \
        /tmp/runtime-library-paths.txt; \
    : > /tmp/runtime-packages.txt; \
    while IFS= read -r lib; do \
        [ -e "$lib" ] || continue; \
        real="$(readlink -f "$lib")"; \
        case "$real" in \
            /usr/local/*) continue ;; \
        esac; \
        owner="$(dpkg-query -S "$real" 2>/dev/null | \
            head -n 1 | cut -d: -f1 || true)"; \
        if [ -z "$owner" ]; then \
            echo "ERROR: Cannot identify the Debian package owning $real"; \
            exit 1; \
        fi; \
        printf '%s\n' "$owner" >> /tmp/runtime-packages.txt; \
    done < /tmp/runtime-library-paths.txt; \
    sort -u -o /tmp/runtime-packages.txt /tmp/runtime-packages.txt; \
    echo "Required runtime Debian packages:"; \
    cat /tmp/runtime-packages.txt; \
    test -s /tmp/runtime-packages.txt


# ==============================================================================
# STAGE 2: RUNTIME
# Only runtime dependencies and installed artifacts
# ==============================================================================
FROM debian:trixie-slim AS runtime

ENV DEBIAN_FRONTEND=noninteractive

# ------------------------------------------------------------------------------
# 8. Install runtime packages discovered by the builder
# ------------------------------------------------------------------------------
COPY --from=builder /tmp/runtime-packages.txt \
    /tmp/runtime-packages.txt

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        passwd \
        $(cat /tmp/runtime-packages.txt) && \
    rm -rf /var/lib/apt/lists/* /tmp/runtime-packages.txt


# ------------------------------------------------------------------------------
# 9. Copy compiled software and configuration
# ------------------------------------------------------------------------------
COPY --from=builder /usr/local/ /usr/local/

COPY --from=builder /etc/c-icap/ /etc/c-icap/

# Includes classification.config, reference.config, and threshold.config.
COPY --from=builder /etc/suricata/ /etc/suricata/


# ------------------------------------------------------------------------------
# 10. Create runtime account and directories
# ------------------------------------------------------------------------------
RUN set -eux; \
    groupadd --system c-icap; \
    useradd --system \
        --gid c-icap \
        --home-dir /nonexistent \
        --no-create-home \
        --shell /usr/sbin/nologin \
        c-icap; \
    mkdir -p \
        /etc/icapsuricata \
        /var/lib/suricata \
        /var/log/suricata \
        /var/log/c-icap \
        /var/run/c-icap; \
    ldconfig


# ------------------------------------------------------------------------------
# 11. Verify runtime files and dependencies
# ------------------------------------------------------------------------------
RUN set -eux; \
    test -x /usr/local/bin/c-icap; \
    test -f /usr/local/lib/libsuricata.so; \
    test -f /usr/local/lib/c_icap/srv_suricata.so; \
    test -s /etc/suricata/classification.config; \
    test -s /etc/suricata/reference.config; \
    test -s /etc/suricata/threshold.config; \
    ldconfig; \
    for target in \
        /usr/local/bin/c-icap \
        /usr/local/lib/libsuricata.so \
        /usr/local/lib/c_icap/srv_suricata.so; \
    do \
        echo "=== Checking $target ==="; \
        output="$(ldd "$target" 2>&1 || true)"; \
        printf '%s\n' "$output"; \
        if printf '%s\n' "$output" | grep -q 'not found'; then \
            echo "ERROR: Missing runtime dependency for $target"; \
            exit 1; \
        fi; \
    done


# ------------------------------------------------------------------------------
# 12. Runtime entry point
# ------------------------------------------------------------------------------
EXPOSE 1344

CMD ["/bin/sh", "-ec", "install -d -o c-icap -g c-icap /var/run/c-icap /var/log/c-icap /var/log/suricata /usr/local/var/run/suricata; exec /usr/local/bin/c-icap -N -D -f /etc/c-icap/c-icap.conf"]
