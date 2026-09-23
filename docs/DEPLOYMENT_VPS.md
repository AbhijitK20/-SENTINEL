# SENTINEL Deployment Guide

Single VPS deployment with systemd, nginx, and SQLite.

## Prerequisites

- Ubuntu 22.04+ or Debian 12+
- Python 3.11+
- 4GB RAM minimum (8GB recommended)
- Public IP with DNS configured

## Quick Start

```bash
# 1. Install system dependencies
sudo apt update && sudo apt install -y python3 python3-venv nginx certbot

# 2. Create sentinel user
sudo useradd -m -s /bin/bash sentinel
sudo usermod -aG sudo sentinel

# 3. Clone and install
sudo -u sentinel bash -c '
cd /home/sentinel
git clone https://github.com/AbhijitK20/-SENTINEL.git sentinel
cd sentinel
curl -LsSf https://astral.sh/uv/install.sh | sh
source "$HOME/.local/bin/env"
uv sync --all-extras
'

# 4. Train models (use the project training script for your dataset)
sudo -u sentinel bash -c '
cd /home/sentinel/sentinel
source .venv/bin/activate
python -c "
from sentinel.baseline import train_baseline, BaselineConfig
    from sentinel.cic_ids2017 import build_labelled_states, load_flow_csv
# ... train on your data
"
'

# 5. Create SQLite database
sudo -u sentinel bash -c '
cd /home/sentinel/sentinel
source .venv/bin/activate
python -c "
from sentinel.db import Database
db = Database(\"/home/sentinel/sentinel/data/sentinel.db\")
db.init_schema()
print(\"Database initialized\")
"
'

# 6. Set environment
sudo -u sentinel bash -c '
cat > /home/sentinel/sentinel/.env << EOF
SENTINEL_DB_PATH=/home/sentinel/sentinel/data/sentinel.db
SENTINEL_BOOTSTRAP_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
SENTINEL_API_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
SENTINEL_ALERT_THRESHOLD=medium
EOF
chmod 600 /home/sentinel/sentinel/.env
'

# 7. Install systemd service
sudo cp deploy/systemd/sentinel-flow-sensor.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable sentinel-flow-sensor
sudo systemctl start sentinel-flow-sensor

# 8. Configure nginx reverse proxy
sudo tee /etc/nginx/sites-available/sentinel << 'EOF'
server {
    listen 443 ssl http2;
    server_name sentinel.yourdomain.com;

    ssl_certificate /etc/letsencrypt/live/sentinel.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/sentinel.yourdomain.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8501;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    location /api/ {
        proxy_pass http://127.0.0.1:8100/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}

server {
    listen 80;
    server_name sentinel.yourdomain.com;
    return 301 https://$host$request_uri;
}
EOF

sudo ln -sf /etc/nginx/sites-available/sentinel /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx

# 9. Get SSL certificate
sudo certbot --nginx -d sentinel.yourdomain.com

# 10. Start dashboard
sudo -u sentinel bash -c '
cd /home/sentinel/sentinel
source .venv/bin/activate
streamlit run src/sentinel/dashboard/app.py --server.port 8501 --server.headless=true
'
```

## Systemd Service (Dashboard)

```bash
sudo tee /etc/systemd/system/sentinel-dashboard.service << 'EOF'
[Unit]
Description=SENTINEL Dashboard
After=network.target

[Service]
Type=simple
User=sentinel
WorkingDirectory=/home/sentinel/sentinel
EnvironmentFile=/home/sentinel/sentinel/.env
ExecStart=/home/sentinel/sentinel/.venv/bin/streamlit run src/sentinel/dashboard/app.py --server.port 8501 --server.headless=true
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl enable sentinel-dashboard
sudo systemctl start sentinel-dashboard
```

## Systemd Service (API)

```bash
sudo tee /etc/systemd/system/sentinel-api.service << 'EOF'
[Unit]
Description=SENTINEL REST API
After=network.target

[Service]
Type=simple
User=sentinel
WorkingDirectory=/home/sentinel/sentinel
EnvironmentFile=/home/sentinel/sentinel/.env
ExecStart=/home/sentinel/sentinel/.venv/bin/uvicorn sentinel.api:create_app --factory --host 127.0.0.1 --port 8100
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl enable sentinel-api
sudo systemctl start sentinel-api
```

## Nginx Configuration

```nginx
server {
    listen 443 ssl http2;
    server_name sentinel.yourdomain.com;

    ssl_certificate /etc/letsencrypt/live/sentinel.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/sentinel.yourdomain.com/privkey.pem;

    # Dashboard
    location / {
        proxy_pass http://127.0.0.1:8501;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    # API
    location /api/ {
        proxy_pass http://127.0.0.1:8100/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `SENTINEL_DB_PATH` | none | SQLite database path (enables SQLite mode) |
| `SENTINEL_BOOTSTRAP_KEY` | none | Bootstrap admin API key |
| `SENTINEL_API_KEY` | none | Flow sensor API key |
| `SENTINEL_ALERT_THRESHOLD` | `low` | Minimum severity for webhook alerts |
| `SENTINEL_WEBHOOK_URL` | none | Generic webhook URL |
| `SENTINEL_SLACK_WEBHOOK` | none | Slack incoming webhook URL |
| `SENTINEL_ALERT_EMAIL` | none | Email for alerts |

## Monitoring

```bash
# Check services
sudo systemctl status sentinel-dashboard sentinel-api sentinel-flow-sensor

# View logs
journalctl -u sentinel-dashboard -f
journalctl -u sentinel-api -f
journalctl -u sentinel-flow-sensor -f

# Check API health
curl http://127.0.0.1:8100/health

# Check flow sensor
sudo systemctl status sentinel-flow-sensor
```

## Backup

```bash
# Backup SQLite database
sudo -u sentinel cp /home/sentinel/sentinel/data/sentinel.db /home/sentinel/sentinel/data/sentinel.db.bak

# Backup models
sudo -u sentinel tar czf /home/sentinel/backup-models.tar.gz /home/sentinel/sentinel/models/
```
