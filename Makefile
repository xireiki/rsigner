TARGET  := target/release/rsigner

.PHONY: all release strip clean

all: release

release:
	cargo build --release

strip: release
	strip $(TARGET)
	ls -lh $(TARGET)

clean:
	cargo clean
