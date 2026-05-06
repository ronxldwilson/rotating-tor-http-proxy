#!/bin/bash

function log() {
    if [[ $# == 1 ]]; then
        level="info"
        msg=$1
    elif [[ $# == 2 ]]; then
        level=$1
        msg=$2
    fi
    echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") [controller] [${level}] ${msg}"
}

if ((TOR_INSTANCES < 1 || TOR_INSTANCES > 200)); then
    log "fatal" "TOR_INSTANCES must be 1-200"
    exit 1
fi

if ((TOR_REBUILD_INTERVAL < 600)); then
    log "fatal" "TOR_REBUILD_INTERVAL must be >= 600 seconds"
    exit 2
fi

cp /etc/tor/torrc.default /etc/tor/torrc

if [[ -n $TOR_EXIT_COUNTRY ]]; then
    IFS=', ' read -r -a countries <<< "$TOR_EXIT_COUNTRY"
    value=""
    is_first=1
    for country in "${countries[@]}"; do
        country=$(xargs <<< "$country")
        [[ ${#country} -ne 2 ]] && continue
        [[ $is_first -ne 1 ]] && value="$value," || is_first=0
        value="$value{$country}"
    done
    country_str=$(tr '[:upper:]' '[:lower:]' <<< "$value")
    if [[ -n $country_str ]]; then
        echo "ExitNodes ${country_str} StrictNodes 1" >> /etc/tor/torrc
        log "Exit nodes limited to: ${TOR_EXIT_COUNTRY}"
    fi
fi

# --- single Tor process serving all virtual instances via SOCKS5 auth isolation ---
tor_data_dir="/var/local/tor/0"
mkdir -p "${tor_data_dir}" && chmod 700 "${tor_data_dir}"

log "Starting single Tor process (${TOR_INSTANCES} virtual instances via SOCKS5 auth)..."
(tor \
  --PidFile "${tor_data_dir}/tor.pid" \
  --dataDirectory "${tor_data_dir}" 2>&1 |
  sed -r "s/^(\w+ [0-9 :.]+)(\[.*)[\r\n]?$/$(date -u +"%Y-%m-%dT%H:%M:%SZ") [tor] \2/") &

log "Waiting for Tor to build first circuit..."
until curl -s -x "socks5h://i0:x@127.0.0.1:10000" --max-time 15 http://checkip.amazonaws.com >/dev/null 2>&1; do
    sleep 3
done
log "Tor ready"

# --- start proxy ---
log "Starting rotating proxy (${TOR_INSTANCES} virtual instances)..."
/tor-proxy &

log "Waiting 10 seconds for circuits to settle..."
sleep 10
curl -sx http://127.0.0.1:3128 https://www.apple.com >/dev/null && log "Proxy ready"

# --- periodic exit IP check ---
while :; do
    log "Sleeping ${TOR_REBUILD_INTERVAL}s before circuit check..."
    sleep "${TOR_REBUILD_INTERVAL}"
    log "Checking exit IPs..."
    for ((i = 0; i < TOR_INSTANCES; i++)); do
        ip=$(curl -s -x "socks5h://i${i}:x@127.0.0.1:10000" --max-time 15 http://checkip.amazonaws.com 2>/dev/null || echo "unavailable")
        log "Instance #${i} exit IP: ${ip}"
    done
done
