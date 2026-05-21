#!/bin/sh
# Runs on the regular internet (NOT in the vpn network namespace).
# Verifies that the PIA-forwarded port is reachable from outside the VPN.
set -e

MAX_ATTEMPTS=30
RETRY_DELAY=3

# Wait for listener-ready, probe-token, and external-ip to all be present
echo "Prober: waiting for listener-ready signal..."
until [ -f /shared/listener-ready ] && [ -f /shared/probe-token ] && [ -f /shared/external-ip ]; do
    sleep 1
done

PORT=$(cat /shared/forwarding-port)
IP=$(cat /shared/external-ip)
EXPECTED_TOKEN=$(cat /shared/probe-token)

echo "Prober: testing port forwarding — connecting to $IP:$PORT from outside the VPN"

i=1
while [ "$i" -le "$MAX_ATTEMPTS" ]; do
    # Connect and read what the listener sends back (4s timeout)
    RECEIVED=$(nc -w 4 "$IP" "$PORT" </dev/null 2>/dev/null | tr -d '[:space:]')
    if [ "$RECEIVED" = "$EXPECTED_TOKEN" ]; then
        echo "SUCCESS: port $PORT is reachable at $IP and returned the correct probe token"
        exit 0
    elif [ -n "$RECEIVED" ]; then
        echo "  attempt $i/$MAX_ATTEMPTS: got unexpected response (token mismatch — wrong listener?)"
    else
        echo "  attempt $i/$MAX_ATTEMPTS: no response, retrying in ${RETRY_DELAY}s..."
    fi
    i=$((i + 1))
    sleep "$RETRY_DELAY"
done

echo "FAIL: port $PORT at $IP did not return the correct probe token after $MAX_ATTEMPTS attempts"
exit 1
