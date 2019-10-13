TARGET=noone

CC=gcc # 指定编译器
STD=gnu11  # centos7 上的 gcc 只支持 gnu99
CFLAGS=-O3 -std=$(STD) -Wall
SRCS=$(wildcard src/*.c) # 查找指定目录下所有 .c 文件，返回字符串
OBJS=$(patsubst src/%.c, build/%.o, $(SRCS)) # 把字符串中的 src/*.c 替换 build/*.o，返回字符串
LIBS=-lcrypto  # openssl

# 找不到 .o 依赖时，自动执行下面语句，逐个生成 .o 文件
$(TARGET):$(OBJS)
	$(CC) $(OBJS) -o build/$(TARGET) $(CFLAGS) $(LIBS)

# $@：规则中的目标
# $<：规则中的第一个依赖
# $^：规则中的所有依赖
build/%.o:src/%.c
	$(CC) -c $< -o $@ $(CFLAGS)

.PONEY: clean
clean:
	rm $(OBJS)