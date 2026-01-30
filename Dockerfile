FROM python:3.12-slim

# Install Tailscale and networking tools
RUN apt-get update && apt-get install -y curl iptables && \
    curl -fsSL https://tailscale.com/install.sh | sh && \
    apt-get clean

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Make start script executable
RUN chmod +x start.sh

# Render uses the PORT environment variable
EXPOSE 10000

CMD ["./start.sh"]