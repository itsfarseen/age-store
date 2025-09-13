# Docker CI tests for different operating systems

REPO_ROOT := $(shell git rev-parse --show-toplevel)
TEST_FILTER ?=

.PHONY: ubuntu arch alpine all

ubuntu:
	@echo "=== Building Ubuntu CI Docker image ==="
	docker build -f Dockerfile.ci -t age-store-ci-ubuntu .
	@echo "=== Running tests in Ubuntu Docker ==="
	docker run --rm -it \
		-v "$(REPO_ROOT):/workspace:ro" \
		-e TEST_FILTER="$(TEST_FILTER)" \
		age-store-ci-ubuntu

arch:
	@echo "=== Building Arch Linux CI Docker image ==="
	docker build -f Dockerfile.ci-arch -t age-store-ci-arch .
	@echo "=== Running tests in Arch Linux Docker ==="
	docker run --rm -it \
		-v "$(REPO_ROOT):/workspace:ro" \
		-e TEST_FILTER="$(TEST_FILTER)" \
		age-store-ci-arch

alpine:
	@echo "=== Building Alpine Linux CI Docker image ==="
	docker build -f Dockerfile.ci-alpine -t age-store-ci-alpine .
	@echo "=== Running tests in Alpine Linux Docker ==="
	docker run --rm -it \
		-v "$(REPO_ROOT):/workspace:ro" \
		-e TEST_FILTER="$(TEST_FILTER)" \
		age-store-ci-alpine

all: ubuntu arch alpine