NAME="sapling"

all: ./pkg/$NAME_bg.wasm

./pkg/$NAME_bg.wasm:
	wasm-pack build --release --target web

install: ./pkg/$NAME_bg.wasm
	cp ./pkg/* ../zeos-wallet/src/pkg/

clean:
	cargo clean
	rm -rf ./pkg
