cmake_minimum_required(VERSION 3.7)
project(ISA)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_FLAGS -lpcap -lcrypto)

add_executable(secret src/main.cpp src/network.h src/network.cpp src/client.cpp src/client.h src/server.cpp src/server.h)
