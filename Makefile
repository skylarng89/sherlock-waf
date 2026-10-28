# Sherlock WAF: the only entry point for build, test and tooling tasks.
# Targets that belong to later milestones print "not yet" and succeed.

SHELL := bash
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := help

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)

GOTOOL := go tool -modfile=tools/go.mod
WEB    := pnpm --dir web

define not_yet
	@echo "$(1): not yet (arrives in $(2))"
endef

.PHONY: help
help: ## List targets
	@grep -hE '^[a-zA-Z0-9_-]+:.*## ' $(MAKEFILE_LIST) | sed -E 's/:.*## /\t/' | sort

.PHONY: setup
setup: ## Download Go modules, pinned tools and web dependencies
	go mod download
	go mod download -modfile=tools/go.mod
	$(WEB) install --frozen-lockfile

.PHONY: gen
gen: ## Run code generators (sqlc, oapi-codegen, openapi-typescript)
	$(call not_yet,gen,M1)

.PHONY: web
web: ## Build the dashboard into internal/webui/dist
	find internal/webui/dist -mindepth 1 ! -name .gitkeep -delete
	$(WEB) build

.PHONY: build
build: web ## Build web then the Go binary into bin/sherlock
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/sherlock ./cmd/sherlock

.PHONY: run
run: build ## Run the placeholder server on :9443
	./bin/sherlock run

.PHONY: fmt
fmt: ## Format Go and web sources
	$(GOTOOL) gofumpt -l -w .
	$(WEB) format

.PHONY: test
test: test-go test-web ## Go and web unit tests

.PHONY: test-go
test-go:
	go test -race ./...

.PHONY: test-web
test-web:
	$(WEB) test

.PHONY: test-integration
test-integration: ## Store tests on SQLite and Postgres
	$(call not_yet,test-integration,M3)

.PHONY: ftw
ftw: ## CRS regression with go-ftw
	$(call not_yet,ftw,M2)

.PHONY: e2e
e2e: ## Compose stack and Playwright
	$(call not_yet,e2e,M2)

.PHONY: bench
bench: ## Go benchmarks
	$(call not_yet,bench,M2)

.PHONY: k6
k6: ## Latency and throughput budgets
	$(call not_yet,k6,M2)

.PHONY: lint
lint: lint-go lint-web lint-secrets ## All linters

.PHONY: lint-go
lint-go:
	@test -z "$$($(GOTOOL) gofumpt -l .)" || { echo "gofumpt: unformatted files:"; $(GOTOOL) gofumpt -l .; exit 1; }
	$(GOTOOL) golangci-lint run ./...

.PHONY: lint-web
lint-web:
	$(WEB) lint

.PHONY: lint-secrets
lint-secrets:
	$(GOTOOL) gitleaks dir --config .gitleaks.toml --no-banner --redact .

.PHONY: vuln
vuln: ## Known vulnerabilities in dependencies
	$(GOTOOL) govulncheck ./...

.PHONY: licenses
licenses: ## Dependency licence check
	$(GOTOOL) go-licenses check ./... --ignore github.com/skylarng89/sherlock-waf --allowed_licenses=MIT,BSD-2-Clause,BSD-3-Clause,Apache-2.0,ISC,MPL-2.0

.PHONY: check
check: lint test build ## What CI runs on every PR

.PHONY: release-snapshot
release-snapshot: web ## Build release archives locally without publishing
	$(GOTOOL) goreleaser release --snapshot --clean
