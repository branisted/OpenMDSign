# OpenMDSign — build tooling.
# Toolchain is pinned via mise (mise.toml): Go 1.26.5, Java 21, Maven 3.9.16.
# Run `mise install` once, then these targets work with plain `go`/`mvn` on PATH.

VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
GOOS    ?= $(shell go env GOOS)
GOARCH  ?= $(shell go env GOARCH)
LDFLAGS := -s -w
BIN     := bin
DIST    := dist
JAR     := java/dss-helper/target/dss-helper.jar

.PHONY: all build jar test vet fmt release clean

all: build jar

## build: compile both binaries for the host platform into ./bin
build:
	@mkdir -p $(BIN)
	go build -ldflags "$(LDFLAGS)" -o $(BIN)/openmdsign  ./cmd/openmdsign
	go build -ldflags "$(LDFLAGS)" -o $(BIN)/openmdsignd ./cmd/openmdsignd
	@echo "built $(BIN)/openmdsign, $(BIN)/openmdsignd ($(VERSION))"

## jar: build the EU DSS helper jar (required for XAdES signing/verification)
jar:
	cd java/dss-helper && mvn -q -DskipTests package
	@echo "built $(JAR)"

## test: vet + unit tests (integration tests are env-gated, see docs)
test: vet
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -l -w .

## release: stripped, version-named binaries + the jar into ./dist for GOOS/GOARCH
##   e.g.  make release GOOS=darwin GOARCH=arm64
release: jar
	@mkdir -p $(DIST)/openmdsign-$(VERSION)-$(GOOS)-$(GOARCH)
	GOOS=$(GOOS) GOARCH=$(GOARCH) go build -trimpath -ldflags "$(LDFLAGS)" \
		-o $(DIST)/openmdsign-$(VERSION)-$(GOOS)-$(GOARCH)/openmdsign  ./cmd/openmdsign
	GOOS=$(GOOS) GOARCH=$(GOARCH) go build -trimpath -ldflags "$(LDFLAGS)" \
		-o $(DIST)/openmdsign-$(VERSION)-$(GOOS)-$(GOARCH)/openmdsignd ./cmd/openmdsignd
	cp $(JAR) $(DIST)/openmdsign-$(VERSION)-$(GOOS)-$(GOARCH)/dss-helper.jar
	cp README.md LICENSE $(DIST)/openmdsign-$(VERSION)-$(GOOS)-$(GOARCH)/ 2>/dev/null || true
	cd $(DIST) && tar -czf openmdsign-$(VERSION)-$(GOOS)-$(GOARCH).tar.gz openmdsign-$(VERSION)-$(GOOS)-$(GOARCH)
	@echo "release: $(DIST)/openmdsign-$(VERSION)-$(GOOS)-$(GOARCH).tar.gz"

clean:
	rm -rf $(BIN) $(DIST)
