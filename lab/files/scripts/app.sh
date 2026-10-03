#!/usr/bin/env bash
# Lab app — listener on 9099. monitor.sh curls it every 5 minutes.
exec socat TCP-LISTEN:9099,bind=0.0.0.0,reuseaddr,fork EXEC:/bin/cat
