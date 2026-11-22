#!/usr/bin/env bash
set -eu
umask 077
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="$SCRIPT_DIR/compose.yaml"
ENV_FILE="$SCRIPT_DIR/.env"

if [ ! -f "$ENV_FILE" ]; then
	cp "$SCRIPT_DIR/.env.example" "$ENV_FILE"
	PG_PASS=$(openssl rand -hex 32)
	AUTHENTIK_SECRET_KEY=$(openssl rand -hex 48)

	sed -i "s|^PG_PASS=.*|PG_PASS=$PG_PASS|" "$ENV_FILE"
	sed -i "s|^AUTHENTIK_SECRET_KEY=.*|AUTHENTIK_SECRET_KEY=$AUTHENTIK_SECRET_KEY|" "$ENV_FILE"
	sed -i 's|^COMPOSE_PORT_HTTP=.*|COMPOSE_PORT_HTTP=127.0.0.1:9000|' "$ENV_FILE"

	unset PG_PASS AUTHENTIK_SECRET_KEY
fi

docker compose --project-directory "$SCRIPT_DIR" -f "$COMPOSE_FILE" config --quiet
docker compose --project-directory "$SCRIPT_DIR" -f "$COMPOSE_FILE" down
docker compose --project-directory "$SCRIPT_DIR" -f "$COMPOSE_FILE" up -d