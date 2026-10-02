BINARY := odoo
MODULE := github.com/KomoriNoKage/cli-odoo
VERSION ?= dev
LDFLAGS := -s -w -X $(MODULE)/cmd.Version=$(VERSION)

.PHONY: build test lint cross clean

build:
	go build -ldflags "$(LDFLAGS)" -o $(BINARY) .

test:
	go test ./...

lint:
	go vet ./...

# Cross-compile release binaries into dist/.
# Covers macOS (amd64/arm64), Linux (amd64/arm64), Windows (amd64).
cross:
	mkdir -p dist
	GOOS=darwin  GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-darwin-amd64 .
	GOOS=darwin  GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-darwin-arm64 .
	GOOS=linux   GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-linux-amd64 .
	GOOS=linux   GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-linux-arm64 .
	GOOS=windows GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-windows-amd64.exe .

clean:
	rm -rf dist $(BINARY) $(BINARY).exe coverage.out coverage.html
