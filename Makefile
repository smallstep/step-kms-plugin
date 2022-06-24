PKG?=github.com/smallstep/step-kms-plugin
BINNAME?=step-kms-plugin


# Set V to 1 for verbose output from the Makefile
Q=$(if $V,,@)
PREFIX?=
SRC=$(shell find . -type f -name '*.go' -not -path "./vendor/*")
GOOS_OVERRIDE ?=
OUTPUT_ROOT=output/
RELEASE=./.releases

all: lint test build

ci: test build

.PHONY: all ci

#########################################
# Bootstrapping
#########################################

bootstrap:
	$Q go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

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

ifdef V
$(info    GITHUB_REF is $(GITHUB_REF))
$(info    VERSION is $(VERSION))
endif

#########################################
# Build
#########################################

DATE    := $(shell date -u '+%Y-%m-%d %H:%M UTC')
LDFLAGS := -ldflags='-w -X "cmd.Version=$(VERSION)" -X "cmd.BuildTime=$(DATE)"'

build:
	$Q mkdir -p $(@D)
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
	$Q gofmt -l -s -w $(SRC)

lint:
	$Q golangci-lint run --timeout=30m

.PHONY: fmt lint

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
