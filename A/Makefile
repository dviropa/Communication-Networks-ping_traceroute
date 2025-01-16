# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -g

# Target executable name
TARGET = ping

# Source files
SRC = ping.c

# Default target: build the executable
all: $(TARGET)

# Rule to build the executable
$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC)

# Rule to clean up build artifacts
clean:
	rm -f $(TARGET)

# Rule for running the program with example arguments
run:
	# sudo -S ./ping -a 8.8.8.8 -t 4 -c 4
	sudo -S ./ping -a fe80::20c:29ff:fe18:a727 -t 6 -c 3