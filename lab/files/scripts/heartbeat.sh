#!/usr/bin/env bash
# Cron hourly at :17 (/etc/crontab) — leaves an activity log to use as evidence.
echo "$(date -Is) heartbeat" >>/var/log/lab-heartbeat.log
