BINARY  := tn-mcp-proxy
CMD     := ./cmd/tn-mcp-proxy
BIN_DIR := bin
FUZZTIME ?= 30s
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.DEFAULT_GOAL := build
.PHONY: build build-linux test vet lint fmt clean test-scripts fuzz

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

# Runs every fuzz target (any "func FuzzXxx(f *testing.F)" in a _test.go file)
# one by one for FUZZTIME each. Targets are discovered, so a new one is picked
# up automatically. Crashers are written to <pkg>/testdata/fuzz/<Name>/.
fuzz:
	@set -e; n=0; \
	for file in $$(grep -rlE --exclude-dir=.git --exclude-dir=bin --include='*_test.go' '^func Fuzz[A-Za-z0-9_]*\(' . | sort); do \
		dir=$$(dirname "$$file"); \
		for name in $$(grep -oE '^func Fuzz[A-Za-z0-9_]*' "$$file" | sed 's/^func //'); do \
			echo "==> $$dir $$name ($(FUZZTIME))"; \
			go test -run='^$$' -fuzz="^$$name\$$" -fuzztime=$(FUZZTIME) "$$dir"; \
			n=$$((n+1)); \
		done; \
	done; \
	if [ "$$n" -eq 0 ]; then echo "no fuzz targets found" >&2; exit 1; fi; \
	echo "fuzzed $$n targets"
