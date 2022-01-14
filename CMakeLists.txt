cmake_minimum_required(VERSION 3.12)
project(s7unpack C)

set(CMAKE_C_STANDARD 11)

add_executable(s7unpack s7unpack.c lzp.c)
