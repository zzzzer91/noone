cmake_minimum_required(VERSION 2.8)
project(noone C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_FLAGS "-std=gnu99")

# 添加头文件目录
include_directories(./src)

# .c 和 .h 文件
aux_source_directory(./src SRCS)

# bin
add_executable(noone ${SRCS})
target_link_libraries(noone crypto)

# 测试
add_executable(  # 要排除 server.c
        test
        ./tests/test.c
        ./src/cryptor.c
        ./src/transport.c
        ./src/tcp.c
        ./src/socket.c
        ./src/ae.c
        ./src/buffer.c
        ./src/hashtable.c
        ./src/lru.c
        ./src/dns.c)
target_link_libraries(test crypto)