# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -Werror -O2 -g -std=c11
LDFLAGS = -pthread

# Directories
SRC_DIR = src
INC_DIR = include
BUILD_DIR = build
BIN_DIR = bin
TEST_DIR = tests

# Source files
SRCS = $(wildcard $(SRC_DIR)/*.c)
OBJS = $(SRCS:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o)
TEST_SRCS = $(wildcard $(TEST_DIR)/*.c)
TEST_OBJS = $(TEST_SRCS:$(TEST_DIR)/%.c=$(BUILD_DIR)/%.o)

# Main targets
TARGET = $(BIN_DIR)/nexus
TEST_TARGET = $(BIN_DIR)/test_nexus

# Header files
INCLUDES = -I$(INC_DIR)

# Default target
all: directories $(TARGET)

# Create necessary directories
directories:
	mkdir -p $(SRC_DIR)
	mkdir -p $(INC_DIR)
	mkdir -p $(BUILD_DIR)
	mkdir -p $(BIN_DIR)
	mkdir -p $(TEST_DIR)

# Main program
$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $@ $(LDFLAGS)

# Object files
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# Test program
test: directories $(TEST_TARGET)
	./$(TEST_TARGET)

$(TEST_TARGET): $(filter-out $(BUILD_DIR)/main.o, $(OBJS)) $(TEST_OBJS)
	$(CC) $^ -o $@ $(LDFLAGS)

$(BUILD_DIR)/%.o: $(TEST_DIR)/%.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# Clean build files
clean:
	rm -rf $(BUILD_DIR) $(BIN_DIR)

# Install (requires sudo)
install: all
	@echo "Installing NEXUS (requires sudo)..."
	@sudo install -d $(DESTDIR)/usr/local/bin
	@sudo install -m 755 $(TARGET) $(DESTDIR)/usr/local/bin

# Uninstall (requires sudo)
uninstall:
	@echo "Uninstalling NEXUS (requires sudo)..."
	@sudo rm -f $(DESTDIR)/usr/local/bin/$(notdir $(TARGET))

# Development tools
format:
	find . -name "*.c" -o -name "*.h" | xargs clang-format -i

lint:
	cppcheck --enable=all $(SRC_DIR) $(INC_DIR)

# Dependencies
DEPS = $(OBJS:.o=.d)
-include $(DEPS)

# Debug build
debug: CFLAGS += -DDEBUG -g
debug: all

# Release build
release: CFLAGS += -O3 -DNDEBUG
release: all

# Documentation
docs:
	doxygen Doxyfile

# Project structure
project-structure:
	@mkdir -p $(SRC_DIR)
	@mkdir -p $(INC_DIR)
	@mkdir -p $(TEST_DIR)
	@mkdir -p docs

# Phony targets
.PHONY: all clean test install uninstall format lint debug release docs project-structure directories killall

# File organization
$(shell mkdir -p $(SRC_DIR) $(INC_DIR) $(BUILD_DIR) $(BIN_DIR) $(TEST_DIR))

# Expected directory structure:
# src/
#   main.c
#   nexus.c
# include/
#   nexus.h
# build/
#   *.o
#   *.d
# bin/
#   nexus
#   test_nexus
# tests/
#   test_nexus.c

# Add this with the other targets
killall:
	@echo "Stopping all NEXUS processes..."
	@-pkill -9 nexus 2>/dev/null || true
	@-pkill -9 -f nexus 2>/dev/null || true
	@-rm -f /tmp/nexus.pid 2>/dev/null || true
	@-for port in $$(netstat -tlpn 2>/dev/null | grep :808 | awk '{print $$4}' | cut -d: -f2); do \
		fuser -k -n tcp $$port; \
	done 2>/dev/null || true
	@sleep 1
	@echo "All NEXUS processes stopped"
