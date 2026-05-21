PROJECT=check_http
MAKE:=make
SHELL:=bash
GOVERSION:=$(shell \
    go version | \
    awk -F'go| ' '{ split($$5, a, /\./); printf ("%04d%04d", a[1], a[2]); exit; }' \
)
# also update other go.mod files when changing minimum version
# find . -name go.mod (run make gomods afterwards)
MINGOVERSION:=00010026
MINGOVERSIONSTR:=1.26
BUILD:=$(shell git rev-parse --short HEAD)
REVISION:=$(shell ./buildtools/get_version | awk -F . '{ print $$3 }')
# see https://github.com/go-modules-by-example/index/blob/master/010_tools/README.md
# and https://github.com/golang/go/wiki/Modules#how-can-i-track-tool-dependencies-for-a-module
TOOLSFOLDER=$(shell pwd)/tools
export GOBIN := $(TOOLSFOLDER)
export PATH := $(GOBIN):$(PATH)
GOLANG_CI_OPTIONS=--show-stats=0 --uniq-by-line=0 --timeout=5m

VERSION ?= $(shell ./buildtools/get_version)
GOARCH  ?= $(shell go env GOARCH)
GOOS    ?= $(shell go env GOOS)

GITBASE=github.com/sni/check_http_go
BUILD_FLAGS=-ldflags "-s -w"
TEST_FLAGS=-timeout=5m $(BUILD_FLAGS)

GO=go
CGO_ENABLED=0

.PHONY:

all: build

CMDS = $(shell cd ./cmd && ls -1)

tools: | versioncheck
	set -e; for DEP in $(shell grep "_ " buildtools/tools.go | awk '{ print $$2 }'); do \
		( cd buildtools && $(GO) install $$DEP@latest ) ; \
	done
	( cd buildtools && $(GO) mod tidy )

updatedeps: versioncheck
	$(MAKE) clean
	$(MAKE) tools
	$(GO) mod download
	GOPROXY=direct $(GO) get -t -u ./pkg/* ./pkg/checkhttp ./cmd/*
	$(GO) mod download
	$(MAKE) cleandeps

cleandeps:
	set -e; for dir in $(shell ls -d1 pkg/* pkg/checkhttp cmd/*); do \
		( cd ./$$dir && $(GO) mod tidy ); \
	done
	$(GO) mod tidy
	( cd buildtools && $(GO) mod tidy )

vendor: go.work
	GOWORK=off $(GO) mod vendor

go.work:
	echo "go $(MINGOVERSIONSTR).0" > go.work
	$(GO) work use \
		. \
		buildtools/. \

gomods:
	find . -name go.mod -exec sed -i {} -e "s/^go .*/go $(MINGOVERSIONSTR).0/" \;

build: vendor
	set -e; for CMD in $(CMDS); do \
		( cd ./cmd/$$CMD && CGO_ENABLED=$(CGO_ENABLED) $(GO) build $(BUILD_FLAGS) -o ../../$$CMD ) ; \
	done

build-linux-amd64: vendor
	set -e; for CMD in $(CMDS); do \
		( cd ./cmd/$$CMD && GOOS=linux GOARCH=amd64 CGO_ENABLED=0 $(GO) build $(BUILD_FLAGS) -o ../../$$CMD.linux.amd64 ) ; \
	done

build-linux-arm64: vendor
	set -e; for CMD in $(CMDS); do \
		( cd ./cmd/$$CMD && GOOS=linux GOARCH=arm64 CGO_ENABLED=0 $(GO) build $(BUILD_FLAGS) -o ../../$$CMD.linux.arm64 ) ; \
	done

build-linux-i386: vendor
	set -e; for CMD in $(CMDS); do \
		( cd ./cmd/$$CMD && GOOS=linux GOARCH=386 CGO_ENABLED=0 $(GO) build $(BUILD_FLAGS) -o ../../$$CMD.linux.i386 ) ; \
	done

build-windows-i386: vendor rsrc_windows_386.syso
	set -e; for CMD in $(CMDS); do \
		( cd ./cmd/$$CMD && GOOS=windows GOARCH=386 CGO_ENABLED=0 $(GO) build $(BUILD_FLAGS) -o ../../$$CMD.windows.i386.exe ) ; \
	done

build-windows-amd64: vendor rsrc_windows_amd64.syso
	set -e; for CMD in $(CMDS); do \
		( cd ./cmd/$$CMD && GOOS=windows GOARCH=amd64 CGO_ENABLED=0 $(GO) build $(BUILD_FLAGS) -o ../../$$CMD.windows.amd64.exe ) ; \
	done

build-windows-arm64: vendor rsrc_windows_arm64.syso
	set -e; for CMD in $(CMDS); do \
		( cd ./cmd/$$CMD && GOOS=windows GOARCH=arm64 CGO_ENABLED=0 $(GO) build $(BUILD_FLAGS) -o ../../$$CMD.windows.arm64.exe ) ; \
	done

build-freebsd-i386: vendor
	set -e; for CMD in $(CMDS); do \
		( cd ./cmd/$$CMD && GOOS=freebsd GOARCH=386 CGO_ENABLED=0 $(GO) build $(BUILD_FLAGS) -o ../../$$CMD.freebsd.i386 ) ; \
	done

build-freebsd-amd64: vendor
	set -e; for CMD in $(CMDS); do \
		( cd ./cmd/$$CMD && GOOS=freebsd GOARCH=amd64 CGO_ENABLED=0 $(GO) build $(BUILD_FLAGS) -o ../../$$CMD.freebsd.i386 ) ; \
	done

build-darwin-aarch64: vendor
	set -e; for CMD in $(CMDS); do \
		( cd ./cmd/$$CMD && GOOS=darwin GOARCH=arm64 CGO_ENABLED=$(shell if [ "$(GOOS)" != "darwin" ]; then echo "0"; else echo $(CGO_ENABLED); fi ) $(GO) build $(BUILD_FLAGS) -o ../../$$CMD.darwin.aarch64 ) ; \
	done

clean:
	set -e; for CMD in $(CMDS); do \
		rm -f ./cmd/$$CMD/$$CMD; \
	done

GOVET=$(GO) vet -all
SRCFOLDER=./cmd/. ./pkg/. ./buildtools/.
fmt: tools
	set -e; for CMD in $(CMDS); do \
		$(GOVET) ./cmd/$$CMD; \
	done
	set -e; for dir in $(shell ls -d1 pkg/* t/); do \
		$(GOVET) ./$$dir; \
	done
	gofmt -w -s $(SRCFOLDER)
	./tools/gofumpt -w $(SRCFOLDER)
	./tools/gci write --skip-generated $(SRCFOLDER)
	./tools/goimports -w $(SRCFOLDER)

versioncheck:
	@[ $$( printf '%s\n' $(GOVERSION) $(MINGOVERSION) | sort | head -n 1 ) = $(MINGOVERSION) ] || { \
		echo "**** ERROR:"; \
		echo "**** $(PROJECT) requires at least golang version $(MINGOVERSIONSTR) or higher"; \
		echo "**** this is: $$(go version)"; \
		exit 1; \
	}

golangci: tools
	#
	# golangci combines a few static code analyzer
	# See https://github.com/golangci/golangci-lint
	#
	@which golangci-lint
	@golangci-lint version
	@echo "  - GOOS=linux"; \
	GOOS=linux CGO_ENABLED=0 golangci-lint run $(GOLANG_CI_OPTIONS) pkg/... cmd/...
	@echo "  - GOOS=darwin"; \
	GOOS=darwin CGO_ENABLED=$(shell if [ "$(GOOS)" != "darwin" ]; then echo "0"; else echo $(CGO_ENABLED); fi ) golangci-lint run $(GOLANG_CI_OPTIONS) pkg/... cmd/...
	@echo "  - GOOS=freebsd"; \
	GOOS=freebsd CGO_ENABLED=0 golangci-lint run $(GOLANG_CI_OPTIONS) pkg/... cmd/...
	@echo "  - GOOS=windows"; \
	GOOS=windows CGO_ENABLED=0 golangci-lint run $(GOLANG_CI_OPTIONS) pkg/... cmd/...

govulncheck: tools
	govulncheck ./...

tag:
	git tag v${VERSION}
	git push origin v${VERSION}
	git push origin main

test: build
	( cd ./pkg/checkhttp && $(GO) test $(BUILD_FLAGS) -o ../../check_http.linux.arm64 ) ;
