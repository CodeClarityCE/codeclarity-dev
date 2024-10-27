# Makefile template derivated from https://github.com/dunglas/symfony-docker/blob/main/docs/makefile.md
.DEFAULT_GOAL = help
.PHONY        = help build up down logs

## —— 🦉 CodeClarity's Makefile 🦉 ——————————————————————————————————
help: ## Outputs this help screen
	@grep -E '(^[a-zA-Z0-9_-]+:.*?##.*$$)|(^##)' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}{printf "\033[32m%-30s\033[0m %s\n", $$1, $$2}' | sed -e 's/\[32m##/[33m/'

## —— Commands for the dev env 💻 ———————————————————————————————————————————————————————————————
build: ## Builds the Docker images
	@cd .cloud/scripts && sh build.sh

up: ## Starts the Docker images
	@cd .cloud/scripts && sh up.sh

down: ## Stops the Docker images
	@cd .cloud/scripts && sh down.sh

pull: ## Pulls the Docker images
	docker compose -f .cloud/docker/docker-compose.yaml pull

logs: ## Displays the logs of the Docker images
	@cd .cloud/scripts && sh logs.sh

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
knowledge-setup: export PG_DB_PORT = 5432
knowledge-setup: ## Creates the database
	@set -a ; . .cloud/env/.env.makefile ; set +a; cd backend/services/knowledge && go run main.go -knowledge -action setup && cd -

knowledge-update: export PG_DB_PORT = 6432
knowledge-update: ## Updates the database
	@set -a ; . .cloud/env/.env.makefile ; set +a; cd backend/services/knowledge && go run main.go -knowledge -action update && cd -

## —— Commands to dump and restore database 💾 ———————————————————————————————————————————————————————————————
download-dumps: ## Downloads the database dump
	@sh .cloud/scripts/download-dumps.sh

dump-database: ## Dumps the database
	@cd .cloud/scripts && sh dump-db.sh codeclarity
	@cd .cloud/scripts && sh dump-db.sh knowledge
	@cd .cloud/scripts && sh dump-db.sh config
	@cd .cloud/scripts && sh dump-db.sh plugins

restore-database: ## Restores the database
	@cd .cloud/scripts && sh restore-db.sh codeclarity
	@cd .cloud/scripts && sh restore-db.sh knowledge
	@cd .cloud/scripts && sh restore-db.sh config
	@cd .cloud/scripts && sh restore-db.sh plugins