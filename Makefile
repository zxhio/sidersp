APP := sidersp
MAIN := ./cmd/sidersp
BIN := ./build/$(APP)
CONFIG ?= ./configs/config.example.yaml
GOOS := linux
GOARCH := amd64

.PHONY: build build-all build-xdp run clean test test-unit test-bpf

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

test: test-unit

test-unit:
	go test ./... -v -count=1

test-bpf: build-xdp
	SIDERSP_RUN_BPF_TESTS=1 go test ./internal/dataplane/ -v -count=1 -run TestBPF
