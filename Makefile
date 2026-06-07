CC      := gcc
CFLAGS  := -O2 -s
LDLIBS  := -lcrypto
TARGET  := rsigner

.PHONY: all clean

all: $(TARGET)

$(TARGET): rsigner.c
	$(CC) $(CFLAGS) -o $@ $< $(LDLIBS)

clean:
	rm -f $(TARGET)
