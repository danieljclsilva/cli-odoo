BINARY := odoo
MODULE := github.com/danieljclsilva/cli-odoo
VERSION ?= dev
LDFLAGS := -s -w -X $(MODULE)/cmd.Version=$(VERSION)

.PHONY: build test lint vuln cross clean

build:
	go build -ldflags "$(LDFLAGS)" -o $(BINARY) .

test:
	go test ./...

lint:
	go vet ./...

vuln:
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...

# Cross-compile release binaries into dist/.
cross:
	mkdir -p dist
	CGO_ENABLED=1 GOOS=darwin  GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-darwin-amd64 .
	CGO_ENABLED=1 GOOS=darwin  GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-darwin-arm64 .
	CGO_ENABLED=0 GOOS=linux   GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-linux-amd64 .
	CGO_ENABLED=0 GOOS=linux   GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-linux-arm64 .
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-windows-amd64.exe .

clean:
	rm -rf dist $(BINARY) $(BINARY).exe coverage.out coverage.html
