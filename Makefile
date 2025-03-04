#TARGET = bin/coffin
#SRC = $(wildcard src/*.c)
#OBJ = $(patsubst src/%.c, obj/%.o, $(SRC))

#default: $(TARGET)

#clean:
#	rm -f obj/*.o
#	rm -f bin/*

#$(TARGET): $(OBJ)
#	gcc -o $@ $?

#obj/%.o : src/%.c
#	gcc -c $< -o $@ -Iinclude


# Define variables for better readability
CC = gcc
CFLAGS = -Wall -Wextra -g -Iinclude

# Target executable name and location
TARGET = bin/coffin

# Source files using wildcard
SRC = $(wildcard src/*.c)

# Object files, derived from source files by replacing .c with .o
OBJ = $(patsubst src/%.c, obj/%.o, $(SRC))

# Default target to build the executable
all: $(TARGET)

# Rule to clean up generated files
clean:
	rm -f $(OBJ) $(TARGET)
	rm -rf bin/ obj/

# Ensure output directories exist
bin/:
	mkdir -p $@

obj/:
	mkdir -p $@

# Link object files into an executable
$(TARGET): | bin/
	$(CC) $(CFLAGS) -o $@ $^

# Rule to compile source files into object files
%.o : obj/%.c | obj/
	$(CC) $(CFLAGS) -c $< -o $@

.PHONY: all clean