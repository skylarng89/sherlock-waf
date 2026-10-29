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
gen: ## Run code generators (event schema, sqlc, oapi-codegen, openapi-typescript)
	mkdir -p docs/reference
	go run ./internal/events/schemagen docs/reference/event.schema.json
	$(GOTOOL) sqlc generate
	$(GOTOOL) oapi-codegen -config api/oapi-codegen.yaml api/openapi.yaml
	cd web && pnpm exec openapi-typescript ../api/openapi.yaml -o src/api/schema.d.ts

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

.PHONY: image
image: ## Build a local container image for this machine's architecture as sherlock:dev
	rm -rf .image-ctx && mkdir -p .image-ctx/linux/$(shell go env GOARCH)
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o .image-ctx/linux/$(shell go env GOARCH)/sherlock ./cmd/sherlock
	cp Dockerfile .image-ctx/
	docker build --build-arg TARGETPLATFORM=linux/$(shell go env GOARCH) -t sherlock:dev .image-ctx
	rm -rf .image-ctx

.PHONY: fmt
fmt: ## Format Go and web sources
	$(GOTOOL) gofumpt -l -w .
	$(WEB) format

.PHONY: test
test: test-go test-web ## Go and web unit tests

.PHONY: test-go
test-go:
	go test -race -tags sherlock_testhooks ./...

.PHONY: test-web
test-web:
	$(WEB) test

.PHONY: test-integration
test-integration: ## Store tests on SQLite and Postgres
	$(call not_yet,test-integration,M3)

.PHONY: corpus
corpus: ## Replay the benign corpus at PL1 (zero blocks) and the known-false-positive tripwire
	go test -count=1 -run 'TestBenignCorpusHasNoBlocksAtPL1|TestKnownFalsePositivesStayDocumented' ./internal/dataplane/waf

.PHONY: ftw
ftw: ## CRS regression (go-ftw) at one paranoia level: make ftw [PL=1..4]
	test/ftw/run.sh $(or $(PL),1)

.PHONY: ftw-all
ftw-all: ## CRS regression at paranoia levels 1 to 4 (nightly)
	@for pl in 1 2 3 4; do test/ftw/run.sh $$pl || exit 1; done

E2E_COMPOSE := docker compose -f test/e2e-compose/compose.yaml
export SHERLOCK_HTTP_PORT ?= 18080
export SHERLOCK_ADMIN_PORT ?= 19443
export JUICE_DIRECT_PORT ?= 13000

.PHONY: e2e-up
e2e-up: ## Build the binary and start Sherlock + Juice Shop + httpbin (waits until healthy)
	CGO_ENABLED=0 go build -trimpath -o bin/sherlock ./cmd/sherlock
	$(E2E_COMPOSE) up --build -d --wait --wait-timeout 180

.PHONY: e2e-down
e2e-down: ## Stop and remove the compose stack
	$(E2E_COMPOSE) down -v --remove-orphans

.PHONY: e2e
e2e: e2e-up ## Compose smoke test (Playwright joins in M4); always tears the stack down
	@trap '$(MAKE) --no-print-directory e2e-down' EXIT; test/e2e-compose/smoke.sh

.PHONY: e2e-ui
e2e-ui: ## Browser e2e + axe suite (Playwright); builds dashboard and binary, fresh data dirs
	$(WEB) e2e

.PHONY: bench
bench: ## Go benchmarks; writes bench.txt (use BASE=<file> with bench-gate to compare)
	go test -run '^$$' -bench . -benchmem -count 6 ./internal/... | tee bench.txt

.PHONY: bench-gate
bench-gate: ## Fail if bench.txt is >10% slower than BASE (a previous bench.txt)
	@test -n "$(BASE)" || { echo "usage: make bench-gate BASE=path/to/old-bench.txt"; exit 2; }
	scripts/bench-gate.sh "$(BASE)" bench.txt

.PHONY: k6
k6: ## NFR-1/NFR-2 latency and throughput (needs Docker for k6; see docs/plan/benchmarks.md)
	test/k6/run.sh all

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
