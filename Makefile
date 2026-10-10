BINARY  := tn-mcp-proxy
CMD     := ./cmd/tn-mcp-proxy
BIN_DIR := bin
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.DEFAULT_GOAL := build
.PHONY: build build-linux test vet lint fmt clean test-scripts

build:
	go build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$(BINARY) $(CMD)

build-linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$(BINARY)-linux-amd64 $(CMD)

test:
	go test -race ./...

vet:
	go vet ./...

lint:
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run ./...; \
	else \
		echo "golangci-lint not installed; falling back to go vet"; \
		go vet ./...; \
	fi

fmt:
	gofmt -w .

clean:
	rm -rf $(BIN_DIR) coverage.out

test-scripts:
	scripts/next-version_test.sh
