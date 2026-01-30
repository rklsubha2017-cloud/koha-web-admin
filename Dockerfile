FROM python:3.12-slim

# Install Tailscale and dependencies
RUN apt-get update && \
    curl -fsSL https://tailscale.com/install.sh | sh && \
    apt-get clean

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN chmod +x start.sh

EXPOSE 10000
CMD ["./start.sh"]