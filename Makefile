APP := sidersp
MAIN := ./cmd/sidersp
BIN := ./build/$(APP)
CONFIG ?= ./configs/config.example.yaml

.PHONY: build run clean

build:
	go build -o $(BIN) $(MAIN)

run: build
	$(BIN) -config $(CONFIG)

clean:
	rm -f $(BIN)
