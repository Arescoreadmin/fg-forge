#!/bin/sh
# FrostGate Forge Egress Gateway - nftables setup
# Enforces deny-all egress with optional allowlist profiles

set -e

ALLOWLIST_PROFILE="${EGRESS_ALLOWLIST_PROFILE:-none}"
LOG_PREFIX="FORGE_EGRESS"

echo "[$LOG_PREFIX] Setting up egress gateway (profile: $ALLOWLIST_PROFILE)"

# Flush existing rules
nft flush ruleset 2>/dev/null || true

# Create base table
nft add table inet forge_egress

# Create output chain with default drop
nft add chain inet forge_egress output { type filter hook output priority 0 \; policy drop \; }

# Allow established connections
nft add rule inet forge_egress output ct state established,related accept

# Allow loopback
nft add rule inet forge_egress output oif lo accept

# Allow internal RFC1918 networks
nft add rule inet forge_egress output ip daddr 10.0.0.0/8 accept
nft add rule inet forge_egress output ip daddr 172.16.0.0/12 accept
nft add rule inet forge_egress output ip daddr 192.168.0.0/16 accept

# Allow DNS for internal resolution
nft add rule inet forge_egress output udp dport 53 ip daddr 10.0.0.0/8 accept
nft add rule inet forge_egress output tcp dport 53 ip daddr 10.0.0.0/8 accept

# Apply allowlist profile if specified
case "$ALLOWLIST_PROFILE" in
    "training-updates")
        echo "[$LOG_PREFIX] Applying training-updates allowlist"
        # Allow package repositories for training scenarios
        nft add rule inet forge_egress output tcp dport 443 accept
        nft add rule inet forge_egress output tcp dport 80 accept
        ;;
    "external-api")
        echo "[$LOG_PREFIX] Applying external-api allowlist"
        # Allow specific API endpoints (would be more specific in production)
        nft add rule inet forge_egress output tcp dport 443 accept
        ;;
    "none"|"")
        echo "[$LOG_PREFIX] No allowlist profile - strict deny-all"
        ;;
    *)
        echo "[$LOG_PREFIX] WARNING: Unknown profile '$ALLOWLIST_PROFILE', using deny-all"
        ;;
esac

# Log and drop everything else
nft add rule inet forge_egress output log prefix \"${LOG_PREFIX}_DENY: \" drop

echo "[$LOG_PREFIX] Egress gateway configured"

# Show current ruleset
nft list ruleset

# Keep container running and log denied traffic
echo "[$LOG_PREFIX] Monitoring egress traffic..."
exec tail -f /var/log/messages 2>/dev/null || exec sleep infinity
