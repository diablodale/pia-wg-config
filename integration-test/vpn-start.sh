#!/bin/bash
set -o pipefail

trap 'wg-quick down pia 2>/dev/null; exit' SIGTERM SIGINT SIGQUIT

die() { echo "error: $*" >&2; exit 1; }

# Wait for basic internet connectivity before reaching PIA's API
until dig +time=1 +tries=1 google.com &>/dev/null; do
    sleep 1s
done

# Generate wg config + port-forward state file.
# Credentials come from PIAWGCONFIG_USER / PIAWGCONFIG_PW env vars.
pia-wg-config \
    --region "${PIA_REGION:-swiss}" \
    --outfile /etc/wireguard/pia.conf \
    --pf-state-file /run/pia-pf-state.json \
    || die "pia-wg-config failed to generate config"

# Parse DNS from generated config (needed for resolv.conf inside the tunnel)
DNS=$(awk '/^DNS[[:space:]]*=/{print $3}' /etc/wireguard/pia.conf)
[ -n "$DNS" ] || die "could not parse DNS from generated wg config"

# Write resolv.conf so the container resolves through the tunnel
echo "nameserver $DNS" > /etc/resolv.conf

# Bring the WireGuard tunnel up
wg-quick up /etc/wireguard/pia.conf || die "wg-quick up failed"
wg show pia || die "wg show pia failed — tunnel did not come up"

# Discover the public (PIA exit) IP we appear as from the internet, through the tunnel.
EXTERNAL_IP=$(curl -sf --retry 5 --retry-delay 2 https://ifconfig.me)
[ -n "$EXTERNAL_IP" ] || die "could not determine external IP via ifconfig.me"
echo "$EXTERNAL_IP" > /shared/external-ip
echo "VPN tunnel up. External IP: $EXTERNAL_IP"

# Start the port-forward daemon in the background.
# Capture the assigned port from the "Assigned port NNNNN" line and write it
# to /shared/forwarding-port so the listener and healthcheck can read it.
pia-wg-config port-forward \
    --pf-state-file /run/pia-pf-state.json \
    2>&1 | tee /proc/1/fd/1 | \
    awk '$0 ~ /[Aa]ssigned port [0-9]+/ {
        p = $0; sub(/.*[Aa]ssigned port /, "", p); sub(/[^0-9].*/, "", p);
        print p > "/run/forwarding-port";
        print p > "/shared/forwarding-port";
        fflush();
        exit
    }' &

# Block until the forwarding port is known
until [ -f /shared/forwarding-port ]; do sleep 1s; done
echo "Port forwarding active on port: $(cat /shared/forwarding-port)"

# Generate a random probe token the listener will echo back and the prober will verify.
# Using /dev/urandom avoids any dependency on openssl/uuidgen.
cat /dev/urandom | tr -dc 'a-f0-9' | head -c 32 > /shared/probe-token
echo "Probe token written to /shared/probe-token"

sleep infinity &
wait $!
