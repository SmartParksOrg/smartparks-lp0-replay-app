# Hosted Deployment (systemd + Nginx)

This guide assumes a Linux server with systemd and Nginx installed.

## 1) Create a service user and data directory

```bash
sudo useradd --system --home /opt/lp0-replay --shell /usr/sbin/nologin lp0-replay
sudo mkdir -p /opt/lp0-replay /var/lib/lp0-replay
sudo chown -R lp0-replay:lp0-replay /opt/lp0-replay /var/lib/lp0-replay
```

## 2) Install the app

Copy the repository into `/opt/lp0-replay`, then:

```bash
sudo apt install nodejs npm
cd /opt/lp0-replay
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## 3) Configure environment

```bash
sudo cp deploy/ENV.example /etc/lp0-replay.env
sudo nano /etc/lp0-replay.env
```

Make sure `DATA_DIR=/var/lib/lp0-replay` and set a strong `SECRET_KEY`.
If you install the app somewhere other than `/opt/lp0-replay`, update
`deploy/systemd/lp0-replay.service` before installing it.

## 4) Install systemd unit

```bash
sudo cp deploy/systemd/lp0-replay.service /etc/systemd/system/lp0-replay.service
sudo systemctl daemon-reload
sudo systemctl enable --now lp0-replay
```

The default unit runs with a single worker to keep the in-memory scan cache
consistent. If you need multiple workers later, the scan cache will need to
be moved to a shared store.

## 5) Configure Nginx

```bash
sudo cp deploy/nginx/lp0-replay.conf /etc/nginx/sites-available/lp0-replay.conf
sudo ln -s /etc/nginx/sites-available/lp0-replay.conf /etc/nginx/sites-enabled/lp0-replay.conf
sudo nginx -t
sudo systemctl reload nginx
```

Add TLS/HTTPS per your usual process (certbot, managed certs, etc). Example:

```bash
sudo apt install certbot python3-certbot-nginx
sudo certbot --nginx -d example.com
```

## 6) Log rotation (optional)

```bash
sudo cp deploy/logrotate/lp0-replay /etc/logrotate.d/lp0-replay
```

## 7) Verify

Visit your server in a browser and log in with the default admin credentials.
