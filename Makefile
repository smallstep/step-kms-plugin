PKG?=github.com/smallstep/step-kms-plugin
BINNAME?=step-kms-plugin
GOLANG_CROSS_VERSION?=v1.21.4

# Set V to 1 for verbose output from the Makefile
Q=$(if $V,,@)
PREFIX?=
SRC=$(shell find . -type f -name '*.go' -not -path "./vendor/*")
GOOS_OVERRIDE ?=
OUTPUT_ROOT=output/
RELEASE=./.releases

#########################################
# Default
#########################################

all: lint test build

ci: test build

.PHONY: all ci

#########################################
# Bootstrapping
#########################################

bootstrap:
	$Q curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $$(go env GOPATH)/bin latest
	$Q go install golang.org/x/vuln/cmd/govulncheck@latest
	$Q go install gotest.tools/gotestsum@latest

.PHONY: bootstrap

#################################################
# Determine the type of `push` and `version`
#################################################

# GITHUB Actions
ifdef GITHUB_REF
VERSION ?= $(shell echo $(GITHUB_REF) | sed 's/^refs\/tags\///')
NOT_RC  := $(shell echo $(VERSION) | grep -v -e -rc)
else
VERSION ?= $(shell [ -d .git ] && git describe --tags --always --dirty="-dev")
endif

VERSION := $(shell echo $(VERSION) | sed 's/^v//')
DATE    := $(shell date -u '+%Y-%m-%d %H:%M UTC')

ifdef V
$(info    GITHUB_REF is $(GITHUB_REF))
$(info    VERSION is $(VERSION))
$(info    DATE is $(DATE))
endif

#########################################
# Build
#########################################

LDFLAGS := -ldflags='-s -w -X "$(PKG)/cmd.Version=$(VERSION)" -X "$(PKG)/cmd.ReleaseDate=$(DATE)"'

build:
	$Q go build -v -o $(PREFIX)bin/$(BINNAME) $(LDFLAGS) $(PKG)
	@echo "Build Complete!"

.PHONY: build

#########################################
# Go generate
#########################################

generate: build
	$Q go generate ./...
	$Q mkdir -p completions
	$Q bin/step-kms-plugin completion bash > completions/bash_completion
	$Q bin/step-kms-plugin completion fish > completions/fish_completion
	$Q bin/step-kms-plugin completion powershell > completions/powershell_completion
	$Q bin/step-kms-plugin completion zsh > completions/zsh_completion

.PHONY: generate

#########################################
# Test
#########################################

test:
	$Q go test -coverprofile=coverage.out ./...

.PHONY: test

#########################################
# Linting
#########################################

fmt:
	$Q goimports --local github.com/smallstep/step-kms-plugin  -l -w $(SRC)

lint: golint govulncheck

golint: SHELL:=/bin/bash
golint:
	$Q LOG_LEVEL=error golangci-lint run --config <(curl -s https://raw.githubusercontent.com/smallstep/workflows/master/.golangci.yml) --timeout=30m

govulncheck:
	$Q govulncheck ./...

.PHONY: fmt lint golint govulncheck

#########################################
# Release
#########################################

release-dev:
	$Q @docker run -it --rm --privileged -e CGO_ENABLED=1 \
		--entrypoint /bin/bash \
		-v /var/run/docker.sock:/var/run/docker.sock \
		-v `pwd`:/go/src/$(PKG) \
		-w /go/src/$(PKG) \
		ghcr.io/goreleaser/goreleaser-cross:${GOLANG_CROSS_VERSION}

release-dry-run:
	$Q @docker run --rm --privileged -e CGO_ENABLED=1 \
		--entrypoint /go/src/$(PKG)/docker/build/entrypoint.sh \
		-v /var/run/docker.sock:/var/run/docker.sock \
		-v `pwd`:/go/src/$(PKG) \
		-w /go/src/$(PKG) \
		ghcr.io/goreleaser/goreleaser-cross:${GOLANG_CROSS_VERSION} \
		--clean --skip=validate --skip=publish

release:
	@if [ ! -f ".release-env" ]; then \
		echo "\033[91m.release-env is required for release\033[0m";\
		exit 1;\
	fi
	$Q @docker run --rm --privileged -e CGO_ENABLED=1 --env-file .release-env \
		--entrypoint /go/src/$(PKG)/docker/build/entrypoint.sh \
		-v /var/run/docker.sock:/var/run/docker.sock \
		-v `pwd`:/go/src/$(PKG) \
		-w /go/src/$(PKG) \
		ghcr.io/goreleaser/goreleaser-cross:${GOLANG_CROSS_VERSION} \
		release --clean

.PHONY: release-dev release-dry-run release

#########################################
# Install
#########################################

INSTALL_PREFIX?=/usr/

install: $(PREFIX)bin/$(BINNAME)
	$Q install -D $(PREFIX)bin/$(BINNAME) $(DESTDIR)$(INSTALL_PREFIX)bin/$(BINNAME)

uninstall:
	$Q rm -f $(DESTDIR)$(INSTALL_PREFIX)/bin/$(BINNAME)

.PHONY: install uninstall

#########################################
# Clean
#########################################

clean:
ifneq ($(BINNAME),"")
	$Q rm -f bin/$(BINNAME)
endif

.PHONY: clean
