FROM python:3.12-slim

WORKDIR /app

# Install nftables for network policy management
RUN apt-get update && \
    apt-get install -y --no-install-recommends nftables iproute2 && \
    rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application and scripts
COPY app/ ./app/
COPY scripts/ ./scripts/
RUN chmod +x ./scripts/*.sh

# Note: This container needs NET_ADMIN capability to configure nftables
# Run with: --cap-add=NET_ADMIN

# For non-privileged operation, set DRY_RUN=true
ENV DRY_RUN=true

EXPOSE 8089

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8089"]
