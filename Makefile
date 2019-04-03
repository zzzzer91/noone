CC=gcc # 指定编译器
CFLAGS=-O3
target=noone
src=$(wildcard src/*.c) # 查找指定目录下所有 .c 文件，返回字符串
obj=$(patsubst src/%.c, build/%.o, $(src)) # 把字符串中的 src/*.c 替换 build/*.o，返回字符串
libs=-lcrypto

# 找不到 .o 依赖时，自动执行下面语句，逐个生成 .o 文件
$(target):$(obj)
	$(CC) $(obj) -o build/$(target) -Wall $(CFLAGS) $(libs)

# $@：规则中的目标
# $<：规则中的第一个依赖
# $^：规则中的所有依赖
build/%.o:src/%.c
	$(CC) -c $< -o $@ -Wall $(CFLAGS)

.PONEY: clean
clean:
	rm $(obj)