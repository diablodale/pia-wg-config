#!/bin/sh
# Runs inside the vpn container's network namespace.
# Waits for the forwarded port, then loops-accepts TCP connections on it.
# Writes /shared/listener-ready once nc is about to start so the prober
# knows it is safe to attempt connections.
set -e

until [ -f /shared/forwarding-port ] && [ -f /shared/probe-token ]; do sleep 1; done
PORT=$(cat /shared/forwarding-port)
TOKEN=$(cat /shared/probe-token)
echo "Listener: starting on TCP port $PORT, will echo probe token to callers"

echo ready > /shared/listener-ready

# Each iteration accepts one connection, sends the token, then loops.
while true; do
    echo "$TOKEN" | nc -l -p "$PORT" || true
done
