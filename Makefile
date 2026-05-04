BIN     := androidzip
MODULE  := github.com/palmerc/androidzip
GO      := go
GOFLAGS :=

.PHONY: all build test vet clean install

all: vet build

build:
	$(GO) build $(GOFLAGS) -o $(BIN) .

install:
	$(GO) install $(GOFLAGS) $(MODULE)

test:
	$(GO) test $(GOFLAGS) ./...

vet:
	$(GO) vet ./...

clean:
	rm -f $(BIN)
