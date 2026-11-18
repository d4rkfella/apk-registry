.PHONY: run test build fmt smoke docker-up docker-down

run:
	go run ./cmd/server

test:
	go test ./...

build:
	go build ./cmd/server

fmt:
	gofmt -w cmd internal

smoke:
	./scripts/smoke.sh

docker-up:
	docker compose up --build

docker-down:
	docker compose down
