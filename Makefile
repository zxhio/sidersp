APP := sidersp
MAIN := ./cmd/sidersp
BIN := ./build/$(APP)
CONFIG ?= ./configs/config.example.yaml
GOOS := linux
GOARCH := amd64

.PHONY: build build-all build-xdp run clean

build:
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) go build -trimpath -ldflags="-s -w" -o $(BIN) $(MAIN)

build-xdp:
	go generate ./internal/dataplane

build-all:
	$(MAKE) build-xdp
	$(MAKE) build

run: build-all
	$(BIN) -config $(CONFIG)

clean:
	rm -f $(BIN)
	rm -f ./internal/dataplane/sidersp_bpfel.go
	rm -f ./internal/dataplane/sidersp_bpfel.o
