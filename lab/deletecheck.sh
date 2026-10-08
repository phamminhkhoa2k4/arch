#!/usr/bin/env bash
#
# lab/deletecheck.sh — run delete-check for every ground-truth component
# and print a PASS/FAIL table against ground-truth.yaml (decision D3).
#
#   Usage:  ./lab/deletecheck.sh --db <scan.db> [--rules lab/rules.lab.yaml]
#                                  [--gt lab/ground-truth.yaml] [--bin <path>]
#
# D3 matrix:
#   expected ORPHANED                → verdict ∈ {ORPHANED, LIKELY_ORPHANED}
#   expected ACTIVE/UNKNOWN/BROKEN/EXTERNAL → verdict ∉ {ORPHANED, LIKELY_ORPHANED}
#   plus any must_not_verdict list from the ground truth.
#
# Without --bin the script builds ./cmd/archaeologist into a temp dir.
# Exits 1 when any component FAILs or delete-check errors.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

DB=""
RULES="$SCRIPT_DIR/rules.lab.yaml"
GT="$SCRIPT_DIR/ground-truth.yaml"
BIN=""

while [ $# -gt 0 ]; do
  case "$1" in
    --db) DB="$2"; shift 2 ;;
    --rules) RULES="$2"; shift 2 ;;
    --gt) GT="$2"; shift 2 ;;
    --bin) BIN="$2"; shift 2 ;;
    -h|--help)
      sed -n '2,16p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
      exit 0 ;;
    *) echo "unknown flag: $1" >&2; exit 2 ;;
  esac
done

[ -n "$DB" ] || { echo "FAIL: --db <scan.db> is required" >&2; exit 2; }
[ -f "$DB" ] || { echo "FAIL: db not found: $DB" >&2; exit 2; }
[ -f "$GT" ] || { echo "FAIL: ground truth not found: $GT" >&2; exit 2; }
[ -f "$RULES" ] || { echo "FAIL: rules file not found: $RULES" >&2; exit 2; }

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
if [ -z "$BIN" ]; then
  BIN="$TMP/archaeologist"
  (cd "$ROOT_DIR" && go build -o "$BIN" ./cmd/archaeologist)
fi

# GT id → identity_key/name understood by FindEntities. Cron and timer
# entities need identity keys (their names collide with script/systemd
# twins in the same scan); everything else resolves by name.
ref_for() {
  case "$1" in
    cron-heartbeat)     echo 'cron_job|/etc/crontab#root#/opt/lab/scripts/heartbeat.sh' ;;
    cron-backup)        echo 'cron_job|/etc/cron.d/lab-backup#root#/opt/lab/scripts/backup.sh' ;;
    cron-monthly)       echo 'cron_job|/etc/cron.d/lab-monthly#root#/opt/lab/scripts/monthly-report.sh' ;;
    cron-monitor)       echo 'cron_job|/var/spool/cron/crontabs/root#root#/opt/lab/scripts/monitor.sh' ;;
    cron-rotate-logs)   echo 'cron_job|/var/spool/cron/crontabs/root#root#/opt/lab/scripts/rotate-logs-gone.sh' ;;
    cron-boot)          echo 'cron_job|/etc/cron.d/lab-boot#root#/opt/lab/scripts/boot.sh' ;;
    timer-lab-watchdog) echo 'timer|lab-watchdog.timer' ;;
    route-web)    echo '/web/' ;;
    route-var)    echo '/var/' ;;
    route-dead)   echo '/dead/' ;;
    route-pool)   echo '/pool/' ;;
    route-ext)    echo '/ext/' ;;
    upstream-pool) echo 'lab_pool' ;;
    container-lab-web)      echo 'lab-web' ;;
    container-lab-api)      echo 'lab-api' ;;
    container-lab-cache)    echo 'lab-cache' ;;
    container-lab-helper)   echo 'lab-helper' ;;
    container-lab-worker)   echo 'lab-worker' ;;
    container-lab-old-app)  echo 'lab-old-app' ;;
    unit-lab-app)           echo 'lab-app.service' ;;
    unit-lab-external-api)  echo 'lab-external-api.service' ;;
    unit-lab-batch)         echo 'lab-batch.service' ;;
    unit-lab-legacy)        echo 'lab-legacy.service' ;;
    *) return 1 ;;
  esac
}

# verdict_allowed <expected> <must_not_csv> <got> — decision D3.
verdict_allowed() {
  local exp="$1" mnt="$2" got="$3"
  case "$exp" in
    ORPHANED)
      case "$got" in ORPHANED|LIKELY_ORPHANED) : ;; *) return 1 ;; esac ;;
    *)
      case "$got" in ORPHANED|LIKELY_ORPHANED) return 1 ;; esac ;;
  esac
  if [ -n "$mnt" ]; then
    local IFS=','
    local m
    for m in $mnt; do
      [ "$got" = "$m" ] && return 1
    done
  fi
  return 0
}

echo "=== delete-check vs ground-truth (D3) ==="
echo "db=$DB rules=$RULES"
echo

FAIL=0
COUNT=0
while IFS=$'\t' read -r id expected must_not; do
  [ -n "$id" ] || continue
  COUNT=$((COUNT + 1))
  if ! ref="$(ref_for "$id")"; then
    printf 'FAIL  %-24s no ref mapping for GT id\n' "$id"
    FAIL=1
    continue
  fi
  out="$("$BIN" delete-check "$ref" --db "$DB" --rules-file "$RULES" 2>&1)" || {
    printf 'FAIL  %-24s delete-check error: %s\n' "$id" "$(printf '%s' "$out" | head -1)"
    FAIL=1
    continue
  }
  got="$(printf '%s\n' "$out" | sed -n 's/^Trạng thái: //p' | head -1)"
  if [ -z "$got" ]; then
    printf 'FAIL  %-24s no verdict line\n' "$id"
    FAIL=1
    continue
  fi
  if verdict_allowed "$expected" "$must_not" "$got"; then
    note=""
    [ -n "$must_not" ] && note=" must_not=$must_not"
    printf 'PASS  %-24s expected=%-8s got=%-16s%s\n' "$id" "$expected" "$got" "$note"
  else
    printf 'FAIL  %-24s expected=%-8s got=%-16s\n' "$id" "$expected" "$got"
    printf '%s\n' "$out" | sed 's/^/      | /'
    FAIL=1
  fi
done < <(awk '
  /^components:/ { f = 1; next }
  f && /^[A-Za-z_]+:/ { f = 0 }
  f && /^  - id:/ {
    if (id != "") print id "\t" expd "\t" mnt
    id = $3; expd = ""; mnt = ""
    next
  }
  f && /^    expected:/ { expd = $2 }
  f && /^    must_not_verdict:/ {
    line = $0
    sub(/^.*\[/, "", line); sub(/\].*$/, "", line)
    gsub(/ /, "", line)
    mnt = line
  }
  END { if (id != "") print id "\t" expd "\t" mnt }
' "$GT")

if [ "$COUNT" -eq 0 ]; then
  echo "=== RESULT: FAIL (no components parsed from $GT) ==="
  exit 1
fi

echo
if [ "$FAIL" -ne 0 ]; then
  echo "=== RESULT: FAIL ($COUNT components checked) ==="
  exit 1
fi
echo "=== RESULT: ALL PASS ($COUNT components checked) ==="
