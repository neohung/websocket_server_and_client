CC = gcc
INCLUDE = .
CFLAGS =
OBJ = server.o
LIB = libsha1.a libbase64.a libuuid.a
TARGET = server

%.o: %.c
	@echo [GCC] $@ : $<
	$(CC) -c -o $@ $< $(CFLAGS) -I $(INCLUDE)

%.a: %.o
	@echo [AR] $@ : $<
	ar rcs $@ $<

all: $(OBJ) $(LIB)
	gcc -o $(TARGET) $(OBJ) -L. -lsha1 -lbase64 -luuid

.PHONY: clean
clean:
	rm -f $(TARGET)
	rm -f $(LIB)
	rm -f $(OBJ)

run:
	./$(TARGET)
