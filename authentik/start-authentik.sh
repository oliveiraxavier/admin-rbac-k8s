#!/usr/bin/env bash
set -eu
umask 077
cd authentik
cp .env.example .env
PG_PASS=$(openssl rand -hex 32)
AUTHENTIK_SECRET_KEY=$(openssl rand -hex 48)
sed -i "s|^PG_PASS=.*|PG_PASS=$PG_PASS|" .env
sed -i "s|^AUTHENTIK_SECRET_KEY=.*|AUTHENTIK_SECRET_KEY=$AUTHENTIK_SECRET_KEY|" .env
sed -i 's|^COMPOSE_PORT_HTTP=.*|COMPOSE_PORT_HTTP=127.0.0.1:9000|' .env
unset PG_PASS AUTHENTIK_SECRET_KEY
docker compose config --quiet
docker compose up -d