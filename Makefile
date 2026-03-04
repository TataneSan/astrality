.PHONY: build test tidy artifacts

build:
	go build -o bin/control-plane ./cmd/control-plane
	go build -o bin/agent ./cmd/agent

test:
	go test ./...

tidy:
	go mod tidy

ARTIFACT_VERSION ?= latest

artifacts:
	mkdir -p artifacts
	if [ "$(ARTIFACT_VERSION)" != "latest" ]; then mkdir -p artifacts/$(ARTIFACT_VERSION); fi
	GOOS=linux GOARCH=amd64 go build -o artifacts/astrality-agent-linux-amd64 ./cmd/agent
	GOOS=linux GOARCH=arm64 go build -o artifacts/astrality-agent-linux-arm64 ./cmd/agent
	if [ "$(ARTIFACT_VERSION)" != "latest" ]; then cp artifacts/astrality-agent-linux-amd64 artifacts/$(ARTIFACT_VERSION)/; cp artifacts/astrality-agent-linux-arm64 artifacts/$(ARTIFACT_VERSION)/; fi
