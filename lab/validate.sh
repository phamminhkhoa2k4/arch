#!/usr/bin/env bash
#
# lab/validate.sh — compare the live lab against ground-truth.yaml.
#
#   Usage:  LAB_SSH=root@host [LAB_SSH_KEY=...] ./lab/validate.sh
#   The remote user must be root or have NOPASSWD sudo (uses `sudo -n`).
#
# Prints a PASS/FAIL table; exits 1 when any check FAILs. The EXPECTED values
# must match the counts in lab/ground-truth.yaml.
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

# Must match the counts in lab/ground-truth.yaml
EXPECTED_CONTAINERS=6
EXPECTED_UNITS=4
EXPECTED_CRON=6
EXPECTED_ROUTES=5

FAIL=0
result() { # result <ok?> <label> <detail>
  if [ "$1" = 0 ]; then printf 'PASS  %s (%s)\n' "$2" "$3"; else printf 'FAIL  %s (%s)\n' "$2" "$3"; FAIL=1; fi
}
# check <label> <detail> <cond...> — cond runs under || so set -e does not exit early
check() {
  local label="$1" detail="$2"; shift 2
  local rc=0
  "$@" || rc=1
  result "$rc" "$label" "$detail"
}
eq() { [ "$1" -eq "$2" ]; }
is() { [ "$1" = "$2" ]; }

out="$(ssh "${SSH_OPTS[@]}" "$LAB_SSH" sudo -n bash -s <<'EOF'
set -euo pipefail
c_containers=$(docker ps --format '{{.Names}}' 2>/dev/null | grep -c '^lab-' || true)
c_units=$(ls /etc/systemd/system/lab-*.service 2>/dev/null | wc -l)
c_active=0
for u in lab-app lab-external-api lab-batch; do
  systemctl is-active --quiet "$u.service" && c_active=$((c_active+1)) || true
done
legacy_state="inactive"
systemctl is-active --quiet lab-legacy.service && legacy_state="active" || true
legacy_enabled="disabled"
systemctl is-enabled --quiet lab-legacy.service && legacy_enabled="enabled" || true

c_cron=0
for f in lab-backup lab-monthly lab-boot; do
  [ -f "/etc/cron.d/$f" ] && c_cron=$((c_cron+1))
done
grep -qF '/opt/lab/scripts/heartbeat.sh' /etc/crontab && c_cron=$((c_cron+1)) || true
cr=$(crontab -l 2>/dev/null || true)
printf '%s\n' "$cr" | grep -qF '/opt/lab/scripts/monitor.sh' && c_cron=$((c_cron+1)) || true
printf '%s\n' "$cr" | grep -qF '/opt/lab/scripts/rotate-logs.sh' && c_cron=$((c_cron+1)) || true

c_routes=0
[ -f /etc/nginx/conf.d/lab.conf ] && c_routes=$(grep -c 'location ' /etc/nginx/conf.d/lab.conf || true)

# traps
trap_monthly=no
grep -qE '^0 0 1 \* \*' /etc/cron.d/lab-monthly 2>/dev/null && trap_monthly=yes
trap_external=no
systemctl is-active --quiet lab-external-api.service && trap_external=yes || true
trap_variable=no
grep -q '\$lab_backend' /etc/nginx/conf.d/lab.conf 2>/dev/null && trap_variable=yes

nginx_ok=no
systemctl is-active --quiet nginx && nginx_ok=yes || true

echo "$c_containers $c_units $c_active $legacy_state $legacy_enabled $c_cron $c_routes $trap_monthly $trap_external $trap_variable $nginx_ok"
EOF
)"

read -r c_containers c_units c_active legacy_state legacy_enabled c_cron c_routes \
  trap_monthly trap_external trap_variable nginx_ok <<<"$out"

echo "=== Lab validation vs ground-truth.yaml ==="
check "containers"        "want=$EXPECTED_CONTAINERS got=$c_containers" eq "$c_containers" "$EXPECTED_CONTAINERS"
check "systemd units"     "want=$EXPECTED_UNITS got=$c_units"           eq "$c_units" "$EXPECTED_UNITS"
check "3 units active"    "got=$c_active"                               eq "$c_active" 3
legacy_ok() { is "$legacy_state" inactive && is "$legacy_enabled" enabled; }
check "lab-legacy enabled+inactive (ORPHANED)" "$legacy_enabled/$legacy_state" legacy_ok
check "cron jobs"         "want=$EXPECTED_CRON got=$c_cron"             eq "$c_cron" "$EXPECTED_CRON"
check "nginx routes"      "want=$EXPECTED_ROUTES got=$c_routes"         eq "$c_routes" "$EXPECTED_ROUTES"
check "nginx running"     "$nginx_ok"                                   is "$nginx_ok" yes

echo "--- traps (3) ---"
check "trap monthly_cron"    "0 0 1 * * present"     is "$trap_monthly" yes
check "trap external_caller" "lab-external-api active, no local caller" is "$trap_external" yes
# shellcheck disable=SC2016  # literal $lab_backend in the label, left unexpanded
check "trap nginx_variable"  '$lab_backend in proxy_pass' is "$trap_variable" yes

if [ "$FAIL" -ne 0 ]; then
  echo "=== RESULT: FAIL ==="; exit 1
fi
echo "=== RESULT: ALL PASS ==="
