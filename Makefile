CC      := gcc
CFLAGS  := -O2 -s
LDLIBS  := -lcrypto
HELPER  := aesgcm

.PHONY: all clean

all: $(HELPER)

$(HELPER): aesgcm.c
	$(CC) $(CFLAGS) -o $@ $< $(LDLIBS)

clean:
	rm -f $(HELPER)
