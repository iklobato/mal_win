CC = gcc
CFLAGS = -Wall -Wextra -std=c11
TARGET = cc_client
SOURCE = cc_client.c

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SOURCE)
	$(CC) $(CFLAGS) -o $(TARGET) $(SOURCE)

clean:
	rm -f $(TARGET)
