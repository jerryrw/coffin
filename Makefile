TARGET = bin/coffin
SRC = $(wildcard src/*.c)
OBJ = $(patsubst src/%.c, obj/%.o, $(SRC))

default: $(TARGET)

clean:
	rm -f obj/*.o
	rm -f bin/*

$(TARGET): $(OBJ)
	gcc -o $@ $? -lm

obj/%.o : src/%.c
	gcc -c $< -o $@ -Iinclude
