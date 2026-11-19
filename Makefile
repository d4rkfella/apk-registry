.PHONY: run test race vet lint check vulncheck build fmt fmt-check e2e docker-up docker-down

BINARY ?= bin/apk-registry

run:
	go run ./cmd/server

test:
	go test ./...

race:
	go test -race ./...

vet:
	go vet ./...

lint:
	golangci-lint run ./...

check: fmt-check lint test

vulncheck:
	python3 scripts/check-govulncheck.py

build:
	mkdir -p "$(dir $(BINARY))"
	go build -o "$(BINARY)" ./cmd/server

fmt:
	find cmd internal -type f -name '*.go' -exec gofmt -w {} +

fmt-check:
	@test -z "$$(find cmd internal -type f -name '*.go' -exec gofmt -l {} +)"

e2e:
	./scripts/e2e.sh

docker-up:
	docker compose up --build

docker-down:
	docker compose down
