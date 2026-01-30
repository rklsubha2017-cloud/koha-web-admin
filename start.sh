#!/bin/sh

# 1. Start Tailscale daemon in userspace mode
tailscaled --tun=userspace-networking --socks5-server=localhost:1055 &

# 2. Wait for daemon to be ready
sleep 5

# 3. Authenticate with the CORRECT Auth Key
if [ -n "$TAILSCALE_AUTHKEY" ]; then
    echo "Attempting to bring Tailscale up..."
    tailscale up --authkey=${TAILSCALE_AUTHKEY} --hostname=koha-web-admin
else
    echo "Error: TAILSCALE_AUTHKEY is not set. Skipping Tailscale login."
fi

# 4. Start Flask with Gunicorn (using the -m module flag)
echo "Starting Flask application..."
exec python -m gunicorn -b 0.0.0.0:10000 app:app