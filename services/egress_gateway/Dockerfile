FROM alpine:3.19

# Install nftables and logging tools
RUN apk add --no-cache nftables iproute2

# Copy setup script
COPY scripts/setup_nftables.sh /usr/local/bin/setup_nftables.sh
RUN chmod +x /usr/local/bin/setup_nftables.sh

# Note: This container needs NET_ADMIN capability to configure nftables
# In production, consider running as init container or using CNI plugins

ENTRYPOINT ["/usr/local/bin/setup_nftables.sh"]
