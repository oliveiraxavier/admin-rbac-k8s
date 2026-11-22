#!/usr/bin/env bash
set -eu
cd authentik/
umask 077
docker compose -f compose.yaml down
cd ..