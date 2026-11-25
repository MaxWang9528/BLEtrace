#!/usr/bin/env bash
# bletrace launcher: ./bletrace.sh gui | pull | import FILE | list | show latest | patterns latest
cd "$(dirname "$(readlink -f "$0")")" && exec python3 -m bletrace "$@"
