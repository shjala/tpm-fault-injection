GO_FILES = $(wildcard src/*.go)
C_FILES = $(wildcard src/*.c)
BINARY_NAME = tpm-fault-injection
BUILD_DIR = build
SRC_DIR = src

.PHONY: all
all: $(BUILD_DIR)/$(BINARY_NAME)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

.PHONY: generate
generate:
	cd $(SRC_DIR) && go generate

$(BUILD_DIR)/$(BINARY_NAME): $(BUILD_DIR) generate $(GO_FILES)
	cd $(SRC_DIR) && go build -o ../$(BUILD_DIR)/$(BINARY_NAME) .

.PHONY: clean
clean:
	rm -rf $(BUILD_DIR)
	rm -f $(SRC_DIR)/swtpm_*_bpfel.go
	rm -f $(SRC_DIR)/swtpm_*_bpfel.o

.PHONY: deps
deps:
	go mod download
	go mod tidy

.PHONY: help
help:
	@echo "Available targets:"
	@echo "  all       - Build the project (default)"
	@echo "  generate  - Generate eBPF Go code from C"
	@echo "  clean     - Remove build artifacts"
	@echo "  deps      - Install Go dependencies"
	@echo "  help      - Show this help message"
	@echo ""
	@echo "Prerequisites for eBPF generation:"
	@echo "  - Install LLVM, clang, kernel headers and bpf headers"
