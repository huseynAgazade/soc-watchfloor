COMPOSE = docker compose -f infra/docker-compose.yml

.PHONY: up down build logs ps fmt

up:      ## start the stack
	$(COMPOSE) up --build -d
down:    ## stop the stack
	$(COMPOSE) down
build:   ## build images
	$(COMPOSE) build
logs:    ## tail logs
	$(COMPOSE) logs -f
ps:      ## list services
	$(COMPOSE) ps
