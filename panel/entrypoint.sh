#!/bin/sh
ip route add 10.30.1.0/24 via 10.30.2.254 2>/dev/null || true
exec python -m flask run --host=0.0.0.0 --port=8000
