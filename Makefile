# Makefile template derivated from https://github.com/dunglas/symfony-docker/blob/main/docs/makefile.md
.DEFAULT_GOAL = help
.PHONY        = help build build-prod up down logs restart ps seed reset migrate migrate-codeclarity migrate-knowledge migrate-plugins migrate-config dump-knowledge dump-database

## —— 🦉 CodeClarity's Makefile 🦉 ——————————————————————————————————
help: ## Outputs this help screen
	@grep -E '(^[a-zA-Z0-9_-]+:.*?##.*$$)|(^##)' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}{printf "\033[32m%-30s\033[0m %s\n", $$1, $$2}' | sed -e 's/\[32m##/[33m/'

## —— Commands for the dev env 💻 ———————————————————————————————————————————————————————————————
# Inside the devcontainer these targets go through the broker. SERVICE is optional.
BROKER_SOCKET = /run/codeclarity-broker/broker.sock
BROKER = sh .devcontainer/broker-client.sh

build: ## Builds the Docker images
	@if [ -S $(BROKER_SOCKET) ]; then $(BROKER) build $(SERVICE); else cd .cloud/scripts && sh build.sh; fi

up: ## Starts the Docker images
	@if [ -S $(BROKER_SOCKET) ]; then $(BROKER) up $(SERVICE); else cd .cloud/scripts && sh up.sh; fi

down: ## Stops the Docker images
	@if [ -S $(BROKER_SOCKET) ]; then $(BROKER) down; else cd .cloud/scripts && sh down.sh; fi

pull: ## Pulls the Docker images
	@if [ -S $(BROKER_SOCKET) ]; then $(BROKER) pull; else docker compose -f .cloud/docker/docker-compose.yaml pull; fi

logs: ## Displays the logs of the Docker images (devcontainer needs SERVICE=name)
	@if [ -S $(BROKER_SOCKET) ]; then $(BROKER) logs $(SERVICE); else cd .cloud/scripts && sh logs.sh; fi

restart: ## Restarts one service in the devcontainer (SERVICE=name)
	@$(BROKER) restart $(SERVICE)

ps: ## Lists the agent stack's containers in the devcontainer
	@$(BROKER) ps

seed: ## Restores all databases from deployment/dump in the devcontainer
	@$(BROKER) seed

reset: ## Wipes the agent stack's data, then starts and seeds it in the devcontainer
	@$(BROKER) reset

## —— Commands to test production 🎯 ———————————————————————————————————————————————————————————————
build-prod: ## Builds de production Docker images
	@cd frontend && make build-prod
	@cd api && make build-prod
	@cd backend && make build-prod

up-prod: ## Starts the Docker images in prod mode
	@cd deployment && make up

down-prod: ## Stops the Docker images in prod mode
	@cd deployment && make down

## —— Commands to setup database 💾 ———————————————————————————————————————————————————————————————
knowledge-setup: export PG_DB_PORT = 6433
knowledge-setup: ## Creates the database
	@set -a ; . .cloud/env/.env.makefile ; set +a; cd backend/services/knowledge && go run . -knowledge -action setup && cd -

knowledge-update: export PG_DB_PORT = 6433
knowledge-update: ## Updates the database
	@set -a ; . .cloud/env/.env.makefile ; set +a; cd backend/services/knowledge && go run . -knowledge -action update && cd -

knowledge-update-osv: export PG_DB_PORT = 6433
knowledge-update-osv: ## Updates only the OSV advisories (no NVD key needed)
	@if [ -S $(BROKER_SOCKET) ]; then $(BROKER) knowledge-osv; else set -a ; . .cloud/env/.env.makefile ; set +a; cd backend/services/knowledge && go run . -knowledge -action update-osv; fi

## —— Commands to dump and restore database 💾 ———————————————————————————————————————————————————————————————
download-dumps: ## Downloads the database dump
	@sh deployment/scripts/download-dumps.sh

dump-knowledge: ## Dumps knowledge + config with a manifest, only if the completeness gate passes
	@if [ -S $(BROKER_SOCKET) ]; then $(BROKER) dump-knowledge; else cd .cloud/scripts && sh dump-knowledge.sh; fi

dump-database: ## Dumps codeclarity, then knowledge + config through dump-knowledge
	@cd .cloud/scripts && sh dump-db.sh codeclarity
	@$(MAKE) --no-print-directory dump-knowledge

restore-database: ## Restores the database
	@cd .cloud/scripts && sh restore-db.sh codeclarity
	@cd .cloud/scripts && sh restore-db.sh knowledge
	@cd .cloud/scripts && sh restore-db.sh config
	@cd .cloud/scripts && sh restore-test-db.sh

dump-knowledge-dated: ## Dumps the knowledge + config databases to dated files (LABEL=<label>)
ifndef LABEL
	$(error LABEL is not set. Usage: make dump-knowledge-dated LABEL=<label>)
endif
	@cd .cloud/scripts && sh dump-db-dated.sh $(LABEL)

restore-knowledge-dated: ## Restores the knowledge + config databases from dated files (LABEL=<label>)
ifndef LABEL
	$(error LABEL is not set. Usage: make restore-knowledge-dated LABEL=<label>)
endif
	@cd .cloud/scripts && sh restore-knowledge-dated.sh $(LABEL)

## —— Commands to manage database migrations 📦 ———————————————————————————————————————————————————————————————
migrate: ## Run all database migrations (api)
	@if [ -S $(BROKER_SOCKET) ]; then $(BROKER) migrate; else cd api && make migrate; fi

migrate-codeclarity: ## Run codeclarity DB migrations (api)
	@if [ -S $(BROKER_SOCKET) ]; then $(BROKER) migrate codeclarity; else cd api && make migrate-codeclarity; fi

migrate-knowledge: ## Run knowledge DB migrations (api)
	@if [ -S $(BROKER_SOCKET) ]; then $(BROKER) migrate knowledge; else cd api && make migrate-knowledge; fi

migrate-plugins: ## Run plugins DB migrations (api)
	@if [ -S $(BROKER_SOCKET) ]; then $(BROKER) migrate plugins; else cd api && make migrate-plugins; fi

migrate-config: ## Run config DB migrations (api)
	@if [ -S $(BROKER_SOCKET) ]; then $(BROKER) migrate config; else cd api && make migrate-config; fi
