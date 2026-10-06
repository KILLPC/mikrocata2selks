FROM debian:trixie-slim

ENV DEBIAN_FRONTEND=noninteractive

# Install modern build dependencies from Debian Trixie repositories
RUN apt-get update && apt-get install -y \
    cbindgen \
    liblz4-dev \
    libunwind-dev \
    build-essential \
    git \
    autoconf \
    automake \
    libtool \
    libpcap-dev \
    libnet1-dev \
    libyaml-dev \
    zlib1g-dev \
    libcap-ng-dev \
    make \
    libmagic-dev \
    libjansson-dev \
    pkg-config \
    libpcre2-dev \
    cargo \
    rustc \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Compile Suricata as a shared library (libsuricata)
WORKDIR /tmp
RUN git clone --depth 1 https://github.com/OISF/suricata.git
WORKDIR /tmp/suricata
RUN ./autogen.sh && \
    ./configure --enable-library --disable-gccmarch-native && \
    make && make install-libs && ldconfig

# Build icapsuricata
WORKDIR /tmp
RUN git clone https://github.com/sonertari/icapsuricata.git
WORKDIR /tmp/icapsuricata
RUN make && cp icapsuricata /usr/local/bin/

RUN mkdir -p /var/log/suricata /etc/icapsuricata /etc/suricata

EXPOSE 1344

CMD ["icapsuricata", "-c", "/etc/icapsuricata/icapsuricata.conf", "-F"]
