# Object files to be built from .c and .cpp sources
objects = main.o addr_conv.o output.o

# Compiler: Use g++ for C++ files
CC = gcc
CXX = g++

# Flags for C and C++ (可以根据需要进行调整)
CFLAGS = -Wall -g
CXXFLAGS = -Wall -std=c++20 -g

# Phony targets
.PHONY: all clean

# Default target
all: pcap

# Clean target
clean:
	rm -f pcap *.o

# Rules for building object files from C source files
%.o: %.c
	$(CC) -c $(CFLAGS) $< -o $@

# Rules for building object files from C++ source files
%.o: %.cpp
	$(CXX) -c $(CXXFLAGS) $< -o $@

# Rule for building the final executable
pcap: $(objects)
	$(CXX) $(objects) -o pcap
