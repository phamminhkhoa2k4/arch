#!/usr/bin/env bash
# Cron daily 02:30 — references lab-cache (redis-cli) and lab-batch (systemctl).
redis-cli -h 127.0.0.1 -p 6379 BGSAVE >/dev/null 2>&1 || true
systemctl start --no-block lab-batch.service
echo "$(date -Is) backup done" >>/var/log/lab-backup.log
