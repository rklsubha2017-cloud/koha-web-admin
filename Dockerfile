FROM python:3.12-slim

# 1. Install curl, iptables, and sudo
RUN apt-get update && apt-get install -y curl iptables sudo && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# 2. Install Tailscale
RUN curl -fsSL https://tailscale.com/install.sh | sh

# 3. Start Tailscale and authenticate
RUN tailscale up -authkey=${TAILSCALE_AUTHKEY} --accept-routes


WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN chmod +x start.sh

EXPOSE 10000

CMD ["./start.sh"]