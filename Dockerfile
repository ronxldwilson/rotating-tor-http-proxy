# Stage 1: build the Go rotating proxy (no external deps, stdlib only)
FROM golang:1.22-alpine AS builder
WORKDIR /src
COPY proxy/ .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /tor-proxy .

# Stage 2: runtime — tor only, no privoxy, no haproxy
FROM alpine:latest

ENV \
    TOR_INSTANCES=5 \
    TOR_REBUILD_INTERVAL=1800

EXPOSE 3128/tcp 4444/tcp

COPY tor.cfg start.sh bom.sh /
COPY --from=builder /tor-proxy /tor-proxy

RUN apk --no-cache --no-progress --quiet upgrade && \
    apk --no-cache --no-progress --quiet add tor bash curl && \
    mv /tor.cfg /etc/tor/torrc.default && \
    chmod +x /start.sh /bom.sh /tor-proxy && \
    addgroup proxy && \
    adduser -S -D -u 1000 -G proxy proxy && \
    touch /etc/tor/torrc && \
    chown -R proxy: /etc/tor/ && \
    mkdir -p /var/local/tor && \
    chown -R proxy: /var/local/tor && \
    rm -rf /etc/tor/torrc.sample && \
    find / -xdev -type f -regex '.*-$' -exec rm -f {} \; && \
    rm -rf /var/cache/apk/* /usr/share/doc /usr/share/man/ /usr/share/info/* /var/cache/man/* /tmp/* /etc/fstab && \
    rm -rf /etc/init.d /lib/rc /etc/conf.d /etc/inittab /etc/runlevels /etc/rc.conf && \
    rm -rf /etc/sysctl* /etc/modprobe.d /etc/modules /etc/mdev.conf /etc/acpi

STOPSIGNAL SIGINT

HEALTHCHECK --interval=30s --timeout=10s --retries=3 --start-period=30s \
    CMD curl -sf --proxy http://localhost:3128 http://httpbin.org/ip || exit 1

USER proxy

CMD ["/start.sh"]
