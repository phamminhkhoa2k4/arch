#!/usr/bin/env bash
# Cron weekly (Sun 06:00) — rotates the lab logs.
for f in /var/log/lab-heartbeat.log /var/log/lab-monitor.log; do
  [ -f "$f" ] || continue
  mv -f "$f" "$f.1" 2>/dev/null || true
done
echo "$(date -Is) rotated" >>/var/log/lab-rotate.log
