#!/usr/bin/env bash
#
# lab/inventory.sh — print a stable, sorted snapshot of the lab for diffing.
# Used to prove idempotence: run it twice around up.sh — the diff must be empty.
#
#   Usage:  LAB_SSH=root@host [LAB_SSH_KEY=...] ./lab/inventory.sh
#   The remote user must be root or have NOPASSWD sudo (uses `sudo -n`).
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

ssh "${SSH_OPTS[@]}" "$LAB_SSH" sudo -n bash -s <<'EOF'
set -euo pipefail
echo "# containers"
docker ps -a --format '{{.Names}}\t{{.Image}}\t{{.Status}}' 2>/dev/null | grep '^lab-' | sort || true
echo "# units"
for u in lab-app lab-external-api lab-batch lab-legacy; do
  printf '%s\t%s\t%s\n' "$u" \
    "$(systemctl is-active "$u.service" 2>/dev/null || true)" \
    "$(systemctl is-enabled "$u.service" 2>/dev/null || true)"
done | sort
echo "# cron.d"
md5sum /etc/cron.d/lab-* 2>/dev/null | sort || true
echo "# crontab-root"
crontab -l 2>/dev/null | grep lab || true
echo "# crontab-system"
grep lab /etc/crontab 2>/dev/null || true
echo "# nginx"
md5sum /etc/nginx/conf.d/lab.conf 2>/dev/null || true
grep -E 'location|proxy_pass|set ' /etc/nginx/conf.d/lab.conf 2>/dev/null | sort || true
echo "# scripts"
md5sum /opt/lab/scripts/*.sh 2>/dev/null | sort || true
EOF
