# Chamele0nX Protocol — build, test and quality targets.
#
#   make build     build server, client and tools into ./bin
#   make test      run the full test suite
#   make check     vet + lint + race tests (what CI runs)
#
.PHONY: all build test test-race test-cover vet lint fmt fmt-check check clean diagrams hygiene help

BIN_DIR   ?= bin
VERSION   ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT    ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE      ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS = -s -w \
  -X main.version=$(VERSION) \
  -X main.commit=$(COMMIT) \
  -X main.buildDate=$(DATE)

CMDS = chamele0nx-server chamele0nx-client chamele0nx-validator chamele0nx-profiler

all: check build

## build: compile every command into $(BIN_DIR)
build:
	@mkdir -p $(BIN_DIR)
	@for c in $(CMDS); do \
		echo "  build $$c"; \
		go build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$$c ./cmd/$$c || exit 1; \
	done

## test: run all tests
test:
	go test ./...

## test-race: run all tests under the race detector
test-race:
	go test -race ./...

## test-cover: produce coverage.html
test-cover:
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "coverage report: coverage.html"

## fmt-check: fail if anything is not gofmt -s formatted
fmt-check:
	@out=$$(gofmt -s -l .); \
	if [ -n "$$out" ]; then echo "not gofmt-ed:"; echo "$$out"; exit 1; fi

## vet: run go vet
vet:
	go vet ./...

## fmt: format all Go sources
fmt:
	gofmt -s -w .

## lint: run golangci-lint if installed
lint:
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run; \
	else \
		echo "golangci-lint not installed — skipping"; \
		echo "  go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest"; \
	fi

## check: everything CI runs
check: fmt-check vet lint build test-race hygiene

## diagrams: regenerate the documentation diagrams (English and Russian)
diagrams:
	python3 docs/assets/generate.py

## hygiene: fail if any private data reached the tracked tree
hygiene:
	./scripts/check-no-private-data.sh

## clean: remove build artifacts
clean:
	rm -rf $(BIN_DIR) coverage.out coverage.html

## help: list targets
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/## //'
