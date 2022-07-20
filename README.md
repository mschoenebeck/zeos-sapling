# ZEOS Sapling

A sample application for private and untraceable transactions on EOS(IO). This application is deployed to the [Kylin Testnet](https://www.cryptokylin.io/) as the [ZEOS Demo Application](https://zeos.one/demo)

See also:
- [Token Contract (Sapling)](https://github.com/mschoenebeck/thezeostoken/tree/sapling)
- [JS Wallet (Sapling)](https://github.com/mschoenebeck/zeos-wallet/tree/sapling)

## Description
This application was developed and deployed to the Kylin testnet as proof-of-concept for the ZEOS project. It is a simple and straight forward implementation of a protocol for untraceable transfers of fungible tokens on [EOSIO](https://eos.io/) blockchains. It is inspired by and almost exactly implemented as the [Nightfall](https://github.com/EYBlockchain/nightfall) protocol for private transactions on Ethereum based on zk-SNARK.

## Getting Started

To setup the full workspace clone the dependencies [rustzeos](https://github.com/mschoenebeck/rustzeos), [bellman](https://github.com/mschoenebeck/bellman), the smart contract and the JS wallet as well:

```
mkdir zeos
cd zeos
git clone https://github.com/mschoenebeck/rustzeos.git
git clone https://github.com/mschoenebeck/bellman.git
git clone https://github.com/mschoenebeck/thezeostoken.git
cd thezeostoken && git checkout sapling && cd ..
git clone https://github.com/mschoenebeck/zeos-wallet.git
cd zeos-wallet && git checkout sapling && cd ..
```

Clone this repository:

```
git clone https://github.com/mschoenebeck/zeos-sapling.git
cd zeos-sapling
```

Build the project as Rust library:

```
cargo build
```

Build the project as wasm32 library:

```
make
```

If you have cloned the JS Wallet repository as well (as described in the first step) you can install the compiled wasm32 library to the JS application by running:

```
make install
```

### Dependencies

- [Rust Toolchain](https://www.rust-lang.org/tools/install)

## Help
If you need help join us on [Telegram](https://t.me/ZeosOnEos).

## Authors

Matthias Schönebeck

## License

It's open source. Do with it whatever you want.

## Acknowledgments

Big thanks to EY Blockchain for their awesome whitepaper and, of course, to the Electric Coin Company for developing, documenting and maintaining this awesome open source codebase for zk-SNARKs!

* [Nightfall Whitepaper](https://github.com/EYBlockchain/nightfall/blob/master/doc/whitepaper/nightfall-v1.pdf)
* [Zcash Protocol Specification](https://zips.z.cash/protocol/protocol.pdf)