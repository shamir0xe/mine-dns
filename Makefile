BINARY  := minedns
GO      := go
LDFLAGS := -ldflags="-s -w"

.PHONY: all deps vet build build-linux test clean run

all: build

deps:
	$(GO) mod download
	$(GO) mod tidy

vet: deps
	$(GO) vet ./...

build: vet
	$(GO) build $(LDFLAGS) -o $(BINARY) .

build-linux: vet
	GOOS=linux GOARCH=amd64 $(GO) build $(LDFLAGS) -o $(BINARY)-linux .

test: deps
	$(GO) test ./... -v -race -count=1

clean:
	rm -f $(BINARY) $(BINARY)-linux

run: build
	./$(BINARY)
