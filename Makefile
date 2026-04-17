.PHONY: build clean distclean lint

build:
	cargo build

lint:
	cargo fmt --check
	cargo clippy --all-features -- -D warnings
	mdl .

clean:
	cargo clean -p ma-did

distclean: clean
	rm -rf target
	rm -f Cargo.lock
