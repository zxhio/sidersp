APP := sidersp
MAIN := ./cmd/sidersp
BIN := ./build/$(APP)
CONFIG ?= ./configs/config.example.yaml

.PHONY: build run clean xdp-bpf

build:
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o $(BIN) $(MAIN)

run: build
	$(BIN) -config $(CONFIG)

clean:
	rm -f $(BIN)
	rm -f ./internal/dataplane/sidersp_bpfel.go
	rm -f ./internal/dataplane/sidersp_bpfel.o

xdp-bpf:
	go generate ./internal/dataplane
