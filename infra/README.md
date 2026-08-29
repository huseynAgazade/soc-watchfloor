# infra

`docker-compose.yml` wires the whole stack: web, core, the four MCP servers,
Postgres, Redis and the LiteLLM gateway. `postgres/init.sql` is the schema stub.
`litellm/config.yaml` is the one place you swap the LLM.

```bash
cp ../.env.example ../.env   # fill in secrets
docker compose up --build
```
