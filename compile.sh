#!/bin/bash

# Create bin directory if it doesn't exist
mkdir -p bin

# Compile the project
g++ -std=c++17 \
    src/main.cpp \
    src/packet_analyzer.cpp \
    -I include \
    -I /usr/local/include \
    -L /usr/local/lib \
    -lpcap \
    -lsqlite3 \
    -pthread \
    -o bin/traffic_capture 