CC = gcc
CFLAGS = -Wall -Wextra -std=c11
LDFLAGS = -lpcap -lnet

TARGET = xapp
SRC = main.c device_table.c
OBJ = $(SRC:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(LDFLAGS) $^ -o $@

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) $(TARGET)

.PHONY: all clean
