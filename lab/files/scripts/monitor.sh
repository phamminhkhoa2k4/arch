#!/usr/bin/env bash
# Cron */5 — references lab-app by curling 127.0.0.1:9099.
curl -fsS -m 3 http://127.0.0.1:9099/ >/dev/null 2>&1 || true
echo "$(date -Is) monitored" >>/var/log/lab-monitor.log
