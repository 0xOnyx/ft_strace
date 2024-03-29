cmake_minimum_required(VERSION 3.27)
project(ft_strace C)

set(CMAKE_C_STANDARD 11)

add_executable(ft_strace
        src/main.c
        src/include/syscall_i386_tables.h)

include_directories(src/include)