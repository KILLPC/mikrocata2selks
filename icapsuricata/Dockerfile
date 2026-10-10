
FROM debian:trixie-slim

ENV DEBIAN_FRONTEND=noninteractive

# --------------------------------------------------
# Build dependencies
# --------------------------------------------------
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
    c-icap \
    libicapapi-dev \
    && rm -rf /var/lib/apt/lists/*

# --------------------------------------------------
# Build a pinned, stable Suricata library
# --------------------------------------------------
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

# --------------------------------------------------
# Download icapsuricata
# --------------------------------------------------
WORKDIR /tmp

RUN git clone --depth 1 \
    https://github.com/sonertari/icapsuricata.git

WORKDIR /tmp/icapsuricata

# --------------------------------------------------
# Adapt icapsuricata to Debian c-icap 0.5.10
# --------------------------------------------------
# Debian's API accesses ICAP extension headers via
# req->request_header and ci_headers_value().
#
# Debian's dynamic service loader expects an exported
# service symbol rather than the newer registration
# macro used by the upstream source.
RUN set -eux; \
    sed -i \
        -e 's/ci_icap_request_get_header(req, /ci_headers_value(req->request_header, /g' \
        -e 's/static ci_service_module_t suricata_service = {/ci_service_module_t service = {/' \
        -e '/_CI_DECLARE_SERVICE(suricata_service);/d' \
        srv_suricata.c; \
    ! grep -q 'ci_icap_request_get_header' srv_suricata.c; \
    ! grep -q '_CI_DECLARE_SERVICE(suricata_service)' srv_suricata.c; \
    make CICAP_PREFIX=/usr

# --------------------------------------------------
# Install the ICAP service
# --------------------------------------------------
RUN set -eux; \
    MODULES_DIR="/usr/lib/$(gcc -print-multiarch)/c_icap"; \
    install -D -m 0755 srv_suricata.so \
        "${MODULES_DIR}/srv_suricata.so"; \
    if grep -qE '^[[:space:]]*ServicesDir[[:space:]]+' \
        /etc/c-icap/c-icap.conf; then \
        sed -i -E \
            "s|^[[:space:]]*ServicesDir[[:space:]]+.*|ServicesDir ${MODULES_DIR}|" \
            /etc/c-icap/c-icap.conf; \
    else \
        printf '\nServicesDir %s\n' "${MODULES_DIR}" \
            >> /etc/c-icap/c-icap.conf; \
    fi; \
    printf '\n\
# Suricata ICAP service\n\
Service suricata_service srv_suricata.so\n\
ServiceAlias suricata suricata_service\n\
suricata.Preview 1024\n\
suricata.BufSize 4096\n\
' >> /etc/c-icap/c-icap.conf; \
    mkdir -p /var/log/suricata /etc/icapsuricata /etc/suricata; \
    ldconfig

# --------------------------------------------------
# Runtime
# --------------------------------------------------
EXPOSE 1344

CMD ["c-icap", "-N", "-f", "/etc/c-icap/c-icap.conf"]
