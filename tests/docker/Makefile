# Docker CI tests for different operating systems

REPO_ROOT := $(shell git rev-parse --show-toplevel)
TEST_FILTER ?=

.PHONY: ubuntu-22 ubuntu-24 arch alpine all

ubuntu-22:
	@echo "=== Building Ubuntu 22.04 CI Docker image ==="
	docker build -f Dockerfile.ci-ubuntu22 -t age-store-ci-ubuntu22 .
	@echo "=== Running tests in Ubuntu 22.04 Docker ==="
	docker run --rm \
		-v "$(REPO_ROOT):/workspace:ro" \
		-e TEST_FILTER="$(TEST_FILTER)" \
		age-store-ci-ubuntu22

ubuntu-24:
	@echo "=== Building Ubuntu 24.04 CI Docker image ==="
	docker build -f Dockerfile.ci-ubuntu24 -t age-store-ci-ubuntu24 .
	@echo "=== Running tests in Ubuntu 24.04 Docker ==="
	docker run --rm \
		-v "$(REPO_ROOT):/workspace:ro" \
		-e TEST_FILTER="$(TEST_FILTER)" \
		age-store-ci-ubuntu24

arch:
	@echo "=== Building Arch Linux CI Docker image ==="
	docker build -f Dockerfile.ci-arch -t age-store-ci-arch .
	@echo "=== Running tests in Arch Linux Docker ==="
	docker run --rm \
		-v "$(REPO_ROOT):/workspace:ro" \
		-e TEST_FILTER="$(TEST_FILTER)" \
		age-store-ci-arch

alpine:
	@echo "=== Building Alpine Linux CI Docker image ==="
	docker build -f Dockerfile.ci-alpine -t age-store-ci-alpine .
	@echo "=== Running tests in Alpine Linux Docker ==="
	docker run --rm \
		-v "$(REPO_ROOT):/workspace:ro" \
		-e TEST_FILTER="$(TEST_FILTER)" \
		age-store-ci-alpine

all: ubuntu-22 ubuntu-24 arch alpine
