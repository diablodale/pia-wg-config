# Build context is the repo root (pia-wg-config/)
# Stage 1: build the binary
FROM golang:1.25-alpine AS builder
COPY . /src/
RUN cd /src && go build -buildvcs=false -o /usr/local/bin/pia-wg-config .

# Stage 2: runtime
FROM alpine:3.21

RUN apk add --no-cache \
        wireguard-tools \
        iptables \
        ca-certificates \
        bind-tools \
        curl \
        bash

# Workaround: wg-quick fails in Docker if net.ipv4.conf.all.src_valid_mark is read-only
RUN sed -i -E \
    -e '/net.ipv4.conf.all.src_valid_mark=1/c [[ $proto == -4 ]] && [[ $(sysctl -n net.ipv4.conf.all.src_valid_mark) -ne 1 ]] && cmd sysctl -q net.ipv4.conf.all.src_valid_mark=1' \
    /usr/bin/wg-quick

COPY --from=builder /usr/local/bin/pia-wg-config /usr/local/bin/pia-wg-config
COPY integration-test/vpn-start.sh /vpn-start.sh
RUN chmod +x /vpn-start.sh

WORKDIR /pia
CMD ["/bin/bash", "/vpn-start.sh"]
