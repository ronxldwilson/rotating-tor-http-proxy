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

function start_tor() {
    local i=$1
    local socks_port=$((base_tor_socks_port + i))
    local ctrl_port=$((base_tor_ctrl_port + i))
    local tor_data_dir="/var/local/tor/${i}"
    mkdir -p "${tor_data_dir}" && chmod 700 "${tor_data_dir}"
    (tor \
      --PidFile "${tor_data_dir}/tor.pid" \
      --SocksPort "127.0.0.1:${socks_port}" \
      --ControlPort "127.0.0.1:${ctrl_port}" \
      --dataDirectory "${tor_data_dir}" 2>&1 |
      sed -r "s/^(\w+ [0-9 :.]+)(\[.*)[\r\n]?$/$(date -u +"%Y-%m-%dT%H:%M:%SZ") [tor#${i}] \2/") &
}

if ((TOR_INSTANCES < 1 || TOR_INSTANCES > 40)); then
    log "fatal" "TOR_INSTANCES must be 1-40"
    exit 1
fi

if ((TOR_REBUILD_INTERVAL < 600)); then
    log "fatal" "TOR_REBUILD_INTERVAL must be >= 600 seconds"
    exit 2
fi

base_tor_socks_port=10000
base_tor_ctrl_port=20000

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

# --- Phase 1: boot seed instance and wait for a live circuit ---
log "Bootstrapping seed Tor instance (tor#0)..."
start_tor 0

log "Waiting for tor#0 to build its first circuit..."
until curl -s --socks5-hostname "127.0.0.1:${base_tor_socks_port}" --max-time 15 http://checkip.amazonaws.com >/dev/null 2>&1; do
    sleep 3
done
log "tor#0 circuit ready"

# --- Phase 2: copy descriptor cache into all other instances before starting them ---
seed_dir="/var/local/tor/0"
cache_files=(cached-certs cached-consensus cached-microdesc-consensus cached-microdescs cached-microdescs.new)

if ((TOR_INSTANCES > 1)); then
    log "Seeding relay descriptor cache from tor#0 to remaining instances..."
    for ((i = 1; i < TOR_INSTANCES; i++)); do
        dest_dir="/var/local/tor/${i}"
        mkdir -p "${dest_dir}" && chmod 700 "${dest_dir}"
        for f in "${cache_files[@]}"; do
            [[ -f "${seed_dir}/${f}" ]] && cp "${seed_dir}/${f}" "${dest_dir}/${f}"
        done
    done

    log "Starting remaining $((TOR_INSTANCES - 1)) Tor instances in parallel..."
    for ((i = 1; i < TOR_INSTANCES; i++)); do
        start_tor "$i"
    done
fi

# --- Phase 3: start proxy ---
log "Starting rotating proxy..."
/tor-proxy &

log "Waiting 15 seconds for remaining circuits to settle..."
sleep 15
curl -sx "http://127.0.0.1:3128" https://www.apple.com >/dev/null && log "Proxy ready"

# --- Phase 4: periodic exit IP check ---
while :; do
    log "Sleeping ${TOR_REBUILD_INTERVAL}s before circuit check..."
    sleep "${TOR_REBUILD_INTERVAL}"
    log "Checking exit IPs..."
    for ((i = 0; i < TOR_INSTANCES; i++)); do
        socks_port=$((base_tor_socks_port + i))
        ip=$(curl -s --socks5-hostname "127.0.0.1:${socks_port}" http://checkip.amazonaws.com 2>/dev/null || echo "unavailable")
        log "Tor #${i} exit IP: ${ip}"
    done
done
