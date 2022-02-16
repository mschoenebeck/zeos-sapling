/**
 * Main bellman example taken from: https://docs.rs/bellman/0.10.0/bellman/
 */

use x25519_dalek::{EphemeralSecret, PublicKey};

use rand;
use rand_core::OsRng;
use rand::rngs::OsRng as OsRng2;

use blake2s_simd::{Hash, blake2s as blake2s_simd, Params as blake2s_simd_params};

extern crate rustzeos;
use rustzeos::{KeyPair, Symbol, Note, to_json};

use bellman::{gadgets::{multipack}, groth16::{VerifyingKey, Proof}, groth16};
use bls12_381::Bls12;

use zeos_proofs::circuit::zeos::{Mint, Transfer, Burn, TREE_DEPTH};

use std::fs::File;
use std::io::{BufWriter, BufReader};


fn main()
{
    let alice_secret = EphemeralSecret::new(OsRng);
    let alice_public = PublicKey::from(&alice_secret);
    
    let w = &alice_secret as *const EphemeralSecret as *const curve25519_dalek::scalar::Scalar;
    let alice_secret_scalar: &curve25519_dalek::scalar::Scalar = unsafe {&*w};

    println!("alice sk = {:02x?}", alice_secret_scalar.to_bytes());
    println!("alice pk = {:02x?}", alice_public.to_bytes());

    let h_sk = blake2s_simd_params::new()
        .personal(b"Shaftoes")
        .to_state()
        .update(&alice_secret_scalar.to_bytes())
        .finalize();

    let rnd: [u8; 32] = rand::random();
    println!("rnd = {:02x?}", rnd);
    let kp2 = KeyPair::new(rnd);
    println!("kp2 = {:02x?}", kp2.sk());
    println!("rnd = {:02x?}", rnd);

    let mut arr: [u8; 64] = [0; 64];
    kp2.write_addr(&mut arr);

    println!("kp.sk: {:02x?}", alice_secret_scalar.to_bytes());
    println!("kp2.sk: {:02x?}", kp2.sk());
    println!("kp.pk: {:02x?}", alice_public.to_bytes());
    println!("kp2.pk: {:02x?}", kp2.pk());
    println!("kp.h_sk: {:02x?}", h_sk.as_array());
    println!("kp2.h_sk: {:02x?}", kp2.h_sk());
    println!("kp2.addr: {:02x?}", arr);

    // test Symbol stuff
    let s = Symbol::new(4, "ZEOS".to_string());
    println!("s.value = {}", s.value());
    println!("s.decimals = {}", s.decimals());
    println!("s.precision = {}", s.precision());
    println!("s.name = {}", s.name());

    // test note stuff
    let note = Note::new(10, Symbol::new(4, "ZEOS".to_string()), [42; 32]);
    println!("note.amount = {}", note.amount());
    println!("note.symbol = {}", note.symbol().name());
    println!("note.rho = {:?}", note.rho());
    println!("note.commitment = {:?}", note.commitment(kp2.h_sk()));
    println!("note.nullifier = {:?}", note.nullifier(kp2.sk()));

    // generate params for mint circuit
    let params = {
        let c = Mint {
            amount: None,
            symbol: None,
            rho: None,
            h_sk: None,
        };
        groth16::generate_random_parameters::<Bls12, _, _>(c, &mut OsRng2).unwrap()
    };
/*
    // write params to file 'mint.params'
    let f = File::create("mint.params").expect("couldn't create `./mint.params`");
    let mut f = BufWriter::with_capacity(1024*1024, f);
    params.write(&mut f).expect("couldn't write params");

    // read params from file
    let f = File::open("./mint.params").expect("couldn't open `./mint.params`");
    let f = BufReader::with_capacity(1024*1024, f);
    let params: groth16::Parameters<Bls12> = groth16::Parameters::read(f, true).unwrap();
*/
    println!("Prepare the verification key (for proof verification).");
    let pvk = groth16::prepare_verifying_key(&params.vk);

    println!("Pick test values for Mint circuit.");
    let amount: u64 = 100000;
    let symbol: u64 = 357812230660;
    let rho: [u8; 32] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32];
    let h_sk: [u8; 32] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32];
    let mut note = Vec::new();
    note.extend(amount.to_le_bytes());
    note.extend(symbol.to_le_bytes());
    note.extend(rho.clone());
    note.extend(h_sk.clone());
    let z = blake2s_simd_params::new()
        .personal(b"Shaftoes")
        .to_state()
        .update(&note)
        .finalize();
    println!("z = {:?}", z);

    println!("Create an instance of Mint circuit (with the test values as witnesses).");
    let c = Mint {
        amount: Some(amount),
        symbol: Some(symbol),
        rho: Some(rho),
        h_sk: Some(h_sk)
    };

    println!("Create a Groth16 proof with our parameters.");
    let proof = groth16::create_random_proof(c, &params, &mut OsRng2).unwrap();

    println!("Pack the amount, symbol and note commitment as inputs for proof verification.");
    let mut input_bits = Vec::new();
    let amount_bits = multipack::bytes_to_bits_le(&amount.to_le_bytes());
    let symbol_bits = multipack::bytes_to_bits_le(&symbol.to_le_bytes());
    let z_bits = multipack::bytes_to_bits_le(z.as_array());
    input_bits.extend(amount_bits);
    input_bits.extend(symbol_bits);
    input_bits.extend(z_bits);
    let inputs = multipack::compute_multipacking(&input_bits);

    println!("Check the proof!");
    assert!(groth16::verify_proof(&pvk, &proof, &inputs).is_ok());

    println!("{}", to_json(&params.vk));
    println!("{}", to_json(&proof));
    println!("{}", to_json(&inputs));
}
