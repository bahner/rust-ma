.PHONY: build clean distclean

build:
	cargo build

clean:
	cargo clean -p ma-did

distclean: clean
	rm -rf target
