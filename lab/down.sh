#!/usr/bin/env bash
#
# lab/down.sh — remove everything up.sh added .
#
#   Usage:  LAB_SSH=root@host [LAB_SSH_KEY=...] ./lab/down.sh
#   The remote user must be root or have NOPASSWD sudo (uses `sudo -n`).
#
# Installed packages (docker.io, nginx, socat) are kept — only lab state is cleaned.
# Once down.sh finishes, up.sh can run again from scratch (proof reset).
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Load .env from the repo root (gitignored) — variables already set in the environment win.
ENV_FILE="$SCRIPT_DIR/../.env"
if [ -f "$ENV_FILE" ]; then
  _had_ssh=${LAB_SSH+x}
  _prev_ssh=${LAB_SSH-}
  _had_key=${LAB_SSH_KEY+x}
  _prev_key=${LAB_SSH_KEY-}
  set -a
  # shellcheck disable=SC1090
  . <(tr -d '\r' < "$ENV_FILE")   # tolerate CRLF (editor Windows)
  set +a
  if [ -n "$_had_ssh" ]; then LAB_SSH=$_prev_ssh; fi
  if [ -n "$_had_key" ]; then LAB_SSH_KEY=$_prev_key; fi
fi

: "${LAB_SSH:?LAB_SSH is required — set LAB_SSH env or fill .env at repo root}"
LAB_SSH_KEY="${LAB_SSH_KEY:-}"
SSH_OPTS=(-o BatchMode=yes -o ConnectTimeout=10)
[ -n "$LAB_SSH_KEY" ] && SSH_OPTS+=(-i "$LAB_SSH_KEY")

echo "==> dỡ lab trên $LAB_SSH"
ssh "${SSH_OPTS[@]}" "$LAB_SSH" sudo -n bash -s <<'EOF'
set -euo pipefail

# 1. containers
if [ -f /opt/lab/docker-compose.yml ]; then
  (cd /opt/lab && docker compose down -v --remove-orphans >/dev/null 2>&1) || true
fi

# 2. cron
rm -f /etc/cron.d/lab-backup /etc/cron.d/lab-monthly /etc/cron.d/lab-boot
sed -i '\#/opt/lab/scripts/heartbeat.sh#d' /etc/crontab 2>/dev/null || true
cur="$(crontab -l 2>/dev/null || true)"
if [ -n "$cur" ]; then
  rem="$(printf '%s\n' "$cur" | grep -vF '/opt/lab/scripts/' || true)"
  if [ -n "$rem" ]; then printf '%s\n' "$rem" | crontab -
  else crontab -r 2>/dev/null || true; fi
fi

# 3. systemd
systemctl disable --now lab-app.service lab-external-api.service lab-batch.service lab-legacy.service >/dev/null 2>&1 || true
rm -f /etc/systemd/system/lab-*.service
systemctl daemon-reload

# 4. nginx
rm -f /etc/nginx/conf.d/lab.conf
nginx -t >/dev/null 2>&1 && systemctl reload nginx || true

# 5. payload
rm -rf /opt/lab

echo "OK lab removed (packages docker.io/nginx/socat kept installed)"
EOF

printf 'LAB DOWN — chạy ./lab/up.sh để dựng lại từ đầu.\n'
