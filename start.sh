#!/bin/sh

# Start the Tailscale daemon in the background
# We use --tun=userspace because Render's environment doesn't allow kernel TUN devices
tailscaled --tun=userspace-networking --socks5-server=localhost:1055 &

# Wait a moment for tailscaled to initialize
sleep 2

# Authenticate Tailscale
# The --authkey will be provided via Render Environment Variables
tailscale up --authkey=${TAILSCALE_AUTHKEY} --hostname=koha-web-admin

# Start your Flask app using Gunicorn
# Ensure 'app:app' matches your Flask entry point (filename:variable)
exec gunicorn -b 0.0.0.0:10000 app:app