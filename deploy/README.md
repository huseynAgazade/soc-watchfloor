# Running SOC Watchfloor

The whole stack, on **http://<this-host>:8000/** (admin / the `SEED_ADMIN_PASSWORD`).

## Now, on this machine (no Docker, no root)
```bash
./deploy/run-stack.sh          # start everything, detached (survives your shell)
./deploy/run-stack.sh stop     # stop everything
```
Services + ports: core `:8000`, mcp-soar `:9000`, mcp-roster `:9001`,
mcp-detection `:9002`, splunk-soar-mcp `:9010` (private), chat bridge `:9011`.
Logs land in `deploy/logs/`. Secrets are read from the git-ignored files already
in place (`services/*/secrets.env`, `services/core/.env`, the SOAR skill token).

## Keep it running across reboots (systemd user service, still no root)
```bash
mkdir -p ~/.config/systemd/user
cp deploy/soc-watchfloor.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now soc-watchfloor
loginctl enable-linger "$USER"
```

## The production path (Docker + persistent Postgres)
Once the Docker daemon is available:
```bash
cp .env.example .env      # fill in the tokens
docker compose -f infra/docker-compose.yml up --build -d
```
Same app, but the database is the persistent Postgres volume instead of SQLite.
