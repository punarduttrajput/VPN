#!/bin/sh
# Joins the mesh as the "DNS node" (PRD leak-protection.md M4): generates a
# persistent identity + config on first run, then runs `ferrum up-mesh` so the
# dnsmasq `resolver` service — which shares this container's network namespace
# (compose `network_mode: "service:dns-node"`) — is reachable at this node's
# coordinator-assigned tunnel address. That address is what the coordinator
# advertises to every device via `--dns` (DNS_ADVERTISE in .env).
#
# Check the assigned address on first start:
#   docker compose logs dns-node | grep "assigned tunnel address"
# and make sure DNS_ADVERTISE matches it.
set -eu

CONFIG_DIR=${CONFIG_DIR:-/data}
CONFIG="$CONFIG_DIR/dns-node.toml"

if [ ! -f "$CONFIG" ]; then
    echo "dns-node: generating identity + config (first run)" >&2
    # `ferrum keygen` prints TOML-ready lines: private_key = "…" / public_key  = "…"
    KEYS=$(ferrum keygen)
    # A second throwaway keypair fills the parser-required-but-ignored [peer]
    # block (up-mesh takes its peers from the coordinator).
    PEER_PUB=$(ferrum keygen | grep '^public_key')
    {
        echo "$KEYS" | grep '^private_key'
        echo 'listen_port = 51820'
        # Unused in mesh mode (the coordinator assigns the real address), but
        # required by the config parser.
        echo 'interface_address = "10.100.0.1/32"'
        echo ''
        # This container has no resolvectl/nft; skip the v6 leak-guard attempt.
        echo '[leak_protection]'
        echo 'ipv6 = "off"'
        echo ''
        echo '# Required by the parser, ignored by up-mesh (peers come from the'
        echo '# coordinator).'
        echo '[peer]'
        echo "$PEER_PUB"
        echo 'endpoint = "127.0.0.1:1"'
        echo 'allowed_ips = ["127.0.0.1/32"]'
    } > "$CONFIG"
fi

exec ferrum up-mesh \
    --config "$CONFIG" \
    --coordinator "${COORDINATOR_URL:-http://coordinator:50051}" \
    --endpoint "${DNS_NODE_ENDPOINT:?set DNS_NODE_ENDPOINT in .env (vm-public-ip:51820)}" \
    --name dns-node \
    --token-file /secrets/dns-node-token
