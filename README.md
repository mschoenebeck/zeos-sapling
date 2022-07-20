# ZEOS Sapling

A sample application for private and untraceable transactions on EOS(IO). This application is deployed on the [Kylin Testnet](https://www.cryptokylin.io/) as the [ZEOS Demo Application](https://zeos.one/demo)

See also:
- [Token Contract (Sapling)](https://github.com/mschoenebeck/thezeostoken/tree/sapling)
- [JS Wallet (Sapling)](https://github.com/mschoenebeck/zeos-wallet/tree/sapling)

## Description
This application was developed and deployed to the testnet as a proof-of-concept for the ZEOS project. It is a simple protocol for untraceable transfers of fungible tokens on [EOSIO](https://eos.io/). It is inspired by and almost exactly implemented as the [Nightfall](https://github.com/EYBlockchain/nightfall) protocol for private transactions on Ethereum based on zk-SNARK. The proving system utilized by this application is the original Groth16 implementation of Zcash Sapling. Since the proof verification is too expensive to be executed on chain the [DAPP Network's vCPU Service](https://liquidapps.io/vcpu) is utilized to offload the heavy computation to the DSP nodes. While this approach comes with a potential security trade-off it has the benefit of great scalability and incredibly low transaction costs. The JS wallet which is the UI for this application can be used together with the [Anchor Wallet](https://greymass.com/en/anchor/).

## Getting Started

To setup the full workspace clone the dependencies ([rustzeos](https://github.com/mschoenebeck/rustzeos) and [bellman](https://github.com/mschoenebeck/bellman)), the smart contract and the JS wallet as well:

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

- The [Rust Toolchain](https://www.rust-lang.org/tools/install)

## Authors

Matthias Schönebeck

## License

It's open source. Do with it whatever you want.

## Acknowledgments

Big thanks to EY Blockchain for their awesome whitepaper and, of course, to the Electric Coin Company for developing, documenting and maintaining this awesome zk-SNARK codebase for Zcash!

* [Nightfall Whitepaper](https://github.com/EYBlockchain/nightfall/blob/master/doc/whitepaper/nightfall-v1.pdf)
* [Zcash Protocol Specification](https://zips.z.cash/protocol/protocol.pdf)