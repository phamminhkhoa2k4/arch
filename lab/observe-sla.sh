#!/usr/bin/env bash
#
# lab/observe-sla.sh — sample the observe daemon's CPU and memory for
# the 24h SLA window on the lab host.
#
#   Usage (as root on the lab host):
#     ./observe-sla.sh start    # background sampler → /tmp/observe-sla.log
#     ./observe-sla.sh stop
#     ./observe-sla.sh once     # one sample now (smoke test)
#     ./observe-sla.sh show     # tail of the log
#
# Each sample line: <UTC ts> pid=<n> utime=<ticks> stime=<ticks> rss_kb=<n>
# or pid=<n> state=down|gone when the unit is not running.
#
set -euo pipefail

LOG="${OBSERVE_SLA_LOG:-/tmp/observe-sla.log}"
UNIT=archaeologist-observe.service
INTERVAL="${OBSERVE_SLA_INTERVAL:-300}"
PIDFILE=/tmp/observe-sla.pid

sample_once() {
  local ts pid utime stime rss
  ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  pid=$(systemctl show -p MainPID --value "$UNIT" 2>/dev/null || echo 0)
  if [ -z "${pid:-}" ] || [ "$pid" = "0" ]; then
    echo "$ts pid=0 state=down" >>"$LOG"
    return
  fi
  if [ ! -r "/proc/$pid/stat" ]; then
    echo "$ts pid=$pid state=gone" >>"$LOG"
    return
  fi
  # /proc/<pid>/stat fields 14/15 = utime/stime (comm has no spaces here).
  utime=$(awk '{print $14}' "/proc/$pid/stat")
  stime=$(awk '{print $15}' "/proc/$pid/stat")
  rss=$(awk '/^VmRSS:/{print $2}' "/proc/$pid/status" 2>/dev/null || echo 0)
  echo "$ts pid=$pid utime=$utime stime=$stime rss_kb=${rss:-0}" >>"$LOG"
}

case "${1:-}" in
  start)
    if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
      echo "already running (pid $(cat "$PIDFILE"))"
      exit 0
    fi
    echo "sampling every ${INTERVAL}s -> $LOG"
    # Detach fully: new session, no inherited pipes, so the calling
    # ssh command returns immediately and the sampler survives it.
    setsid "$0" loop </dev/null >>"$LOG" 2>&1 &
    echo $! >"$PIDFILE"
    ;;
  loop)
    while true; do
      sample_once
      sleep "$INTERVAL"
    done
    ;;
  stop)
    if [ -f "$PIDFILE" ]; then
      kill "$(cat "$PIDFILE")" 2>/dev/null || true
      rm -f "$PIDFILE"
    fi
    echo "stopped"
    ;;
  once)
    sample_once
    ;;
  show)
    tail -n 20 "$LOG"
    ;;
  *)
    echo "usage: $0 {start|stop|once|show}" >&2
    exit 2
    ;;
esac
