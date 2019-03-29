cmake_minimum_required(VERSION 3.13)
project(noone C)

set(CMAKE_C_STANDARD 11)
#set(CMAKE_BUILD_TYPE "Debug")
#set(CMAKE_C_FLAGS_DEBUG "$ENV{CFLAGS} -O0 -Wall -g -ggdb")
#set(CMAKE_C_FLAGS_RELEASE "$ENV{CFLAGS} -O3 -Wall")

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
        ./src/log.c
        ./src/cryptor.c
        ./src/transport.c
        ./src/tcp.c
        ./src/socket.c
        ./src/ae.c
        ./src/buffer.c
)
target_link_libraries(test crypto)