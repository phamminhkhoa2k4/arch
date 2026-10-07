#!/usr/bin/env bash
#
# lab/up.sh — provision the ground-truth lab on the VPS over SSH.
#
#   Usage:  LAB_SSH=root@203.0.113.10 [LAB_SSH_KEY=~/.ssh/id_ed25519] ./lab/up.sh
#   or:      fill in .env at the repo root (see .env.example), then run ./lab/up.sh
#   The remote user must be root or have NOPASSWD sudo — every command runs under
#   `sudo -n` (fails fast instead of hanging when privileges are missing).
#
# Authority: lab/ground-truth.yaml.
# Every step is idempotent — re-running creates no duplicates and no errors.
# Scope: only ADDS lab components (docker, nginx, units, cron, scripts, containers);
#        existing services are untouched apart from packages apt must install.
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

SSH_OPTS=(-o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new)
[ -n "$LAB_SSH_KEY" ] && SSH_OPTS+=(-i "$LAB_SSH_KEY")

run() { ssh "${SSH_OPTS[@]}" "$LAB_SSH" sudo -n bash -s; }

step() { printf '\n==> %s\n' "$*"; }

step "1/7 kiểm tra SSH + OS"
run <<'EOF'
set -euo pipefail
. /etc/os-release
case "${ID:-}" in
  ubuntu|debian) ;;
  *) echo "FAIL: unsupported OS '${ID:-unknown}' (cần ubuntu/debian)"; exit 1 ;;
esac
echo "OK host=$(hostname) os=$ID $VERSION_ID"
EOF

step "2/7 cài packages (chỉ khi thiếu)"
run <<'EOF'
set -euo pipefail
missing=()
for p in docker.io nginx socat curl; do
  dpkg -s "$p" >/dev/null 2>&1 || missing+=("$p")
done
if [ "${#missing[@]}" -gt 0 ]; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq "${missing[@]}"
fi

# compose v2: try apt first, fall back to the static binary per architecture
if ! docker compose version >/dev/null 2>&1; then
  apt-get install -y -qq docker-compose-v2 2>/dev/null ||
  apt-get install -y -qq docker-compose-plugin 2>/dev/null || {
    case "$(uname -m)" in
      x86_64) arch=x86_64 ;;
      aarch64|arm64) arch=aarch64 ;;
      *) echo "FAIL: unsupported arch $(uname -m) for compose binary"; exit 1 ;;
    esac
    mkdir -p /usr/local/lib/docker/cli-plugins
    curl -fsSL -o /usr/local/lib/docker/cli-plugins/docker-compose \
      "https://github.com/docker/compose/releases/latest/download/docker-compose-linux-${arch}"
    chmod +x /usr/local/lib/docker/cli-plugins/docker-compose
  }
fi
systemctl enable --now docker >/dev/null 2>&1
echo "OK docker=$(docker --version) compose=$(docker compose version --short)"
EOF

step "3/7 sao chép payload lab → /opt/lab"
mkdir -p /tmp 2>/dev/null || true
tar -C "$SCRIPT_DIR/files" -cf - . | \
  ssh "${SSH_OPTS[@]}" "$LAB_SSH" 'sudo -n mkdir -p /opt/lab && sudo -n tar -C /opt/lab -xf - && echo "OK payload copied"'

step "4/7 systemd units (4) + timer (1)"
run <<'EOF'
set -euo pipefail
chmod +x /opt/lab/scripts/*.sh
install -m 644 /opt/lab/systemd/*.service /etc/systemd/system/
install -m 644 /opt/lab/systemd/*.timer /etc/systemd/system/
systemctl daemon-reload
# 3 unit active: enable --now (idempotent)
systemctl enable --now lab-app.service lab-external-api.service lab-batch.service >/dev/null 2>&1
# lab-legacy: BẬT enable, KHÔNG start → ground truth ORPHANED
systemctl enable lab-legacy.service >/dev/null 2>&1
# timer: enable --now (idempotent) → ground truth ACTIVE
systemctl enable --now lab-watchdog.timer >/dev/null 2>&1
for u in lab-app lab-external-api lab-batch; do
  systemctl is-active --quiet "$u.service" || { echo "FAIL: $u not active"; exit 1; }
done
systemctl is-enabled --quiet lab-legacy.service || { echo "FAIL: lab-legacy not enabled"; exit 1; }
systemctl is-active --quiet lab-legacy.service && { echo "FAIL: lab-legacy must stay inactive"; exit 1; } || true
systemctl is-active --quiet lab-watchdog.timer || { echo "FAIL: lab-watchdog.timer not active"; exit 1; }
echo "OK 4 units + 1 timer"
EOF

step "5/7 cron jobs (6)"
run <<'EOF'
set -euo pipefail
# 3 files in /etc/cron.d
install -m 644 /opt/lab/cron/lab-backup /opt/lab/cron/lab-monthly /opt/lab/cron/lab-boot /etc/cron.d/
# 1 line in /etc/crontab (append when missing)
grep -qF '/opt/lab/scripts/heartbeat.sh' /etc/crontab ||
  echo '17 * * * * root /opt/lab/scripts/heartbeat.sh' >>/etc/crontab
# 2 lines in root's crontab (append when missing); rotate-logs-gone.sh
# intentionally does NOT exist → ground truth ORPHAN_CRON (US-5.4)
cur="$(crontab -l 2>/dev/null || true)"
add=false
printf '%s\n' "$cur" | grep -qF '/opt/lab/scripts/monitor.sh' || add=true
printf '%s\n' "$cur" | grep -qF '/opt/lab/scripts/rotate-logs-gone.sh' || add=true
if $add; then
  {
    printf '%s\n' "$cur"
    printf '%s\n' '*/5 * * * * /opt/lab/scripts/monitor.sh'
    printf '%s\n' '0 6 * * 0 /opt/lab/scripts/rotate-logs-gone.sh'
  } | grep -v '^$' | crontab -
fi
echo "OK 6 cron entries"
EOF

step "6/7 nginx routes (5)"
run <<'EOF'
set -euo pipefail
install -m 644 /opt/lab/nginx/lab.conf /etc/nginx/conf.d/lab.conf
nginx -t >/dev/null || { echo "FAIL: nginx config invalid"; exit 1; }
systemctl enable --now nginx >/dev/null 2>&1
systemctl reload nginx
n=$(grep -c 'location ' /etc/nginx/conf.d/lab.conf)
[ "$n" -eq 5 ] || { echo "FAIL: want 5 locations, got $n"; exit 1; }
echo "OK 5 routes"
EOF

step "7/7 docker compose up (6 containers)"
run <<'EOF'
set -euo pipefail
cd /opt/lab
docker compose up -d --remove-orphans >/dev/null
n=$(docker ps --format '{{.Names}}' | grep -c '^lab-' || true)
[ "$n" -eq 6 ] || { echo "FAIL: want 6 lab containers, got $n"; exit 1; }
echo "OK 6 containers"

# US-6.1/6.2: one request per live route fills lab_access.log, one echo
# guarantees a docker log line. Only /web/ and /pool/ — /var/, /dead/ and
# /ext/ must stay without access-log evidence in ground-truth.
curl -fsS -o /dev/null http://127.0.0.1:8080/web/ || echo "WARN /web/ non-2xx"
curl -fsS -o /dev/null http://127.0.0.1:8080/pool/ || echo "WARN /pool/ non-2xx"
docker exec lab-web sh -c 'echo lab-smoke' >/dev/null 2>&1 || echo "WARN lab-web log smoke failed"
echo "OK access-log traffic + log smoke"
EOF

printf '\nLAB UP — chạy ./lab/validate.sh để đối chiếu ground-truth.\n'
