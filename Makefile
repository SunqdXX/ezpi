VERSION := $(shell sed -n 's/^const Version = "\(.*\)"/\1/p' daemon/main.go)

.PHONY: all build test vet lint dist clean install uninstall

all: build

build:
	cd daemon && go build -ldflags="-s -w" -o ../ezpi .

test:
	cd daemon && go test -race ./...

vet:
	cd daemon && go vet ./...

lint: vet
	@cd daemon && test -z "$$(gofmt -l .)" || { echo "needs gofmt:"; gofmt -l daemon; exit 1; }
	@echo "lint ok"

# Release tarball: the stripped binary, the installer, and the Linux packaging.
dist: clean test lint
	@mkdir -p dist/stage/EzPi
	cd daemon && go build -ldflags="-s -w" -o ../dist/stage/EzPi/ezpi .
	cp install.sh README.md LICENSE dist/stage/EzPi/
	mkdir -p dist/stage/EzPi/packaging
	cp -r packaging/linux dist/stage/EzPi/packaging/
	chmod +x dist/stage/EzPi/install.sh dist/stage/EzPi/ezpi
	cd dist/stage && tar czf ../EzPi-linux-x64.tar.gz EzPi
	@rm -rf dist/stage
	@echo
	@ls -lh dist/*.tar.gz

install: build
	sudo ./install.sh

uninstall:
	sudo ./install.sh --uninstall

clean:
	rm -rf dist ezpi daemon/ezpi daemon/ezpid
