#!/usr/bin/env bash
# TRAP monthly_cron — cron 0 0 1 * * invokes this script (day 1 of each month).
echo "$(date -Is) monthly report" >>/var/log/lab-monthly.log
