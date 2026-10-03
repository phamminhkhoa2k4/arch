#!/usr/bin/env bash
# TRAP external_caller — listener on 9090, NO local caller exists.
# Real traffic comes from another host (simulated: nothing on this machine calls 9090).
exec socat TCP-LISTEN:9090,bind=0.0.0.0,reuseaddr,fork EXEC:/bin/cat
