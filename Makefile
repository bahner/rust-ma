.PHONY: build clean distclean

build:
	cargo build

clean:
	cargo clean -p did-ma

distclean: clean
	rm -rf target
