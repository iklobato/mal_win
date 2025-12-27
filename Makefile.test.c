# Makefile for C Unit Tests
# Tests core parsing and logic functions without network/execution

CC = gcc
CFLAGS = -std=c99 -Wall -Wextra -g -DTEST_MODE
TARGET = test_remote_executor_c
SOURCE = test_remote_executor_c.c

# Default target
all: $(TARGET)

# Build test executable
$(TARGET): $(SOURCE)
	$(CC) $(CFLAGS) -o $(TARGET) $(SOURCE)
	@echo "Build complete: $(TARGET)"

# Run tests
test: $(TARGET)
	@echo "Running unit tests..."
	./$(TARGET)

# Run tests with verbose output
test-verbose: $(TARGET)
	@echo "Running unit tests (verbose)..."
	./$(TARGET) || true

# Clean
clean:
	rm -f $(TARGET) *.o
	@echo "Cleaned test artifacts"

# Help
help:
	@echo "Available targets:"
	@echo "  make          - Build test executable"
	@echo "  make test     - Build and run all tests"
	@echo "  make test-verbose - Run tests with verbose output"
	@echo "  make clean    - Remove build artifacts"

.PHONY: all test test-verbose clean help
