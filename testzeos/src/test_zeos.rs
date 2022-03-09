/**
 * test bench for zeos circuits
 */

use bellman::{
    gadgets::{
        boolean::{AllocatedBit, Boolean},
        multipack,
        blake2s::blake2s as blake2s_gadget,
    },
    groth16::{
        Parameters,
        VerifyingKey,
        Proof
    },
    groth16, Circuit, ConstraintSystem, SynthesisError, multiexp::SourceBuilder,
};

use zeos_proofs::circuit::zeos::{Mint, Transfer, Burn, TREE_DEPTH};
use rustzeos::{to_json, Symbol, Asset};

use bls12_381::Bls12;
use ff::PrimeField;
//use pairing::{Engine, Field};
use rand::rngs::OsRng;

use blake2s_simd::{blake2s as blake2s_simd, Params as blake2s_simd_params};




use std::{fs::File, convert::TryInto, io::Read};
use std::io::{BufWriter, BufReader};

fn main()
{
    
    // generate random params
    //println!("Create parameters for our circuit. In a production deployment these would be generated securely using a multiparty computation.");
    /*
    // Mint circuit
    let params = {
        let c = Mint {
            amount: None,
            symbol: None,
            rho: None,
            h_sk: None,
        };
        groth16::generate_random_parameters::<Bls12, _, _>(c, &mut OsRng).unwrap()
    };
    */
    /*
    // Transfer circuit
    let params = {
        let c = Transfer {
            sk_a: None,
            a: None,
            b: None,
            c: None,
            symbol: None,
            rho_a: None,
            rho_b: None,
            rho_c: None,
            h_sk_b: None,
            auth_path: [None; TREE_DEPTH]
        };
        groth16::generate_random_parameters::<Bls12, _, _>(c, &mut OsRng).unwrap()
    };
    */
    /*
    // Burn circuit
    let params = {
        let c = Burn {
            sk_a: None,
            a: None,
            b: None,
            c: None,
            symbol: None,
            rho_a: None,
            rho_c: None,
            auth_path: [None; TREE_DEPTH]
        };
        groth16::generate_random_parameters::<Bls12, _, _>(c, &mut OsRng).unwrap()
    };
    */
    /*
    // write params to file
    let params_file = File::create("params").unwrap();
    let mut params_file = BufWriter::with_capacity(1024 * 1024, params_file);
    params.write(&mut params_file).unwrap();
    */
    
    // read params from file
    let params_file = File::open("burn.params").expect("couldn't open params file");
    let reader = BufReader::with_capacity(1024*1024, params_file);
    let params: groth16::Parameters<Bls12> = Parameters::read(reader, false).unwrap();


    println!("Prepare the verification key (for proof verification).");
    let pvk = groth16::prepare_verifying_key(&params.vk);

    /*
    println!("Pick test values for Mint circuit.");
    let quantity = Asset::new(100000, Symbol::new(4, "ZEOS".to_string()));
    let amount: u64 = quantity.amount().try_into().unwrap();
    let symbol: u64 = quantity.symbol().value();
    let rho: [u8; 32] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32];
    let h_sk: [u8; 32] = *blake2s_simd_params::new()
        .personal(&[0; 8])
        .to_state()
        .update(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32])
        .finalize().as_array();
    let mut note = Vec::new();
    note.extend(amount.to_le_bytes());
    note.extend(symbol.to_le_bytes());
    note.extend(rho.clone());
    note.extend(h_sk.clone());
    let z = blake2s_simd_params::new()
        .personal(&[0; 8])
        .to_state()
        .update(&note)
        .finalize();

    println!("Create an instance of Mint circuit (with the test values as witnesses).");
    let c = Mint {
        amount: Some(amount),
        symbol: Some(symbol),
        rho: Some(rho),
        h_sk: Some(h_sk)
    };
    */
    /*
    println!("Pick test values for Transfer circuit.");
    let q_a = Asset::new(100000, Symbol::new(4, "ZEOS".to_string()));
    let q_b = Asset::new(100000, Symbol::new(4, "ZEOS".to_string()));
    let q_c = Asset::new(0, Symbol::new(4, "ZEOS".to_string()));
    let sk_a: [u8; 32] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32];
    let mut image = Vec::new();
    image.extend(sk_a.clone());
    let h_sk_a = blake2s_simd_params::new()
        .personal(&[0; 8])
        .to_state()
        .update(&image)
        .finalize();
    let a: u64 = q_a.amount().try_into().unwrap();
    let b: u64 = q_b.amount().try_into().unwrap();
    let c: u64 = q_c.amount().try_into().unwrap();
    let symbol: u64 = q_a.symbol().value();
    let rho_a : [u8; 32] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32];
    let rho_b : [u8; 32] = [2, 3, 4, 5, 6, 7, 8, 9, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32];
    let rho_c : [u8; 32] = [3, 4, 5, 6, 7, 8, 9, 10, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32];
    let h_sk_b : [u8; 32] = *blake2s_simd_params::new()
    .personal(&[0; 8])
    .to_state()
    .update(&[42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42])
    .finalize().as_array();
    // Z_a
    let mut note_a = Vec::new();
    note_a.extend(a.to_le_bytes());
    note_a.extend(symbol.to_le_bytes());
    note_a.extend(rho_a.clone());
    note_a.extend(h_sk_a.as_array().clone());
    let z_a = blake2s_simd_params::new()
        .personal(&[0; 8])
        .to_state()
        .update(&note_a)
        .finalize();
    // Z_b
    let mut note_b = Vec::new();
    note_b.extend(b.to_le_bytes());
    note_b.extend(symbol.to_le_bytes());
    note_b.extend(rho_b.clone());
    note_b.extend(h_sk_b.clone());
    let z_b = blake2s_simd_params::new()
        .personal(&[0; 8])
        .to_state()
        .update(&note_b)
        .finalize();
    // Z_c
    let mut note_c = Vec::new();
    note_c.extend(c.to_le_bytes());
    note_c.extend(symbol.to_le_bytes());
    note_c.extend(rho_c.clone());
    note_c.extend(h_sk_a.as_array().clone());
    let z_c = blake2s_simd_params::new()
        .personal(&[0; 8])
        .to_state()
        .update(&note_c)
        .finalize();
    // N_a
    let mut nf = Vec::new();
    nf.extend(rho_a.clone());
    nf.extend(sk_a.clone());
    let nf_a = blake2s_simd_params::new()
        .personal(&[0; 8])
        .to_state()
        .update(&nf)
        .finalize();
    // auth_path (TREE_DEPTH = 2)
    //       rt
    //      /  \
    //    n1    0
    //   /  \
    // Z_a   0
    // n1
    let mut image = Vec::new();
    image.extend(z_a.as_array().clone());
    image.extend([0; 32]);
    let n1 = blake2s_simd_params::new()
        .personal(&[0; 8])
        .to_state()
        .update(&image)
        .finalize();
    // rt
    let mut image = Vec::new();
    image.extend(n1.as_array().clone());
    image.extend([0; 32]);
    let rt = blake2s_simd_params::new()
        .personal(&[0; 8])
        .to_state()
        .update(&image)
        .finalize();
    let auth_path = [Some(([0; 32], false)), Some(([0; 32], false))];
    */
    /*
    // auth_path (TREE_DEPTH = 2)
    //       rt
    //      /  \
    //    l1    0
    //   /  \
    //  x    Z_a
    let x : [u8; 32] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32];
    // l1
    let mut image = Vec::new();
    image.extend(x.clone());
    image.extend(z_a.as_array().clone());
    let l1 = blake2s_simd_params::new()
        .personal(&[0; 8])
        .to_state()
        .update(&image)
        .finalize();
    // rt
    let mut image = Vec::new();
    image.extend(l1.as_array().clone());
    image.extend([0; 32]);
    let rt = blake2s_simd_params::new()
        .personal(&[0; 8])
        .to_state()
        .update(&image)
        .finalize();
    let auth_path = [Some((x, true)), Some(([0; 32], false))];
    //let auth_path = [Some((x, true))];
    */
    /*
    println!("Create an instance of Transfer circuit (with the test values as witnesses).");
    let c = Transfer {
        sk_a: Some(sk_a),
        a: Some(a),
        b: Some(b),
        c: Some(c),
        symbol: Some(symbol),
        rho_a: Some(rho_a),
        rho_b: Some(rho_b),
        rho_c: Some(rho_c),
        h_sk_b: Some(h_sk_b),
        auth_path: auth_path
    };
    */
    
    println!("Pick test values for Burn circuit.");
    let q_a = Asset::new(100000, Symbol::new(4, "ZEOS".to_string()));
    let q_b = Asset::new(100000, Symbol::new(4, "ZEOS".to_string()));
    let q_c = Asset::new(0, Symbol::new(4, "ZEOS".to_string()));
    let sk_a: [u8; 32] = [42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42];//[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32];
    let mut image = Vec::new();
    image.extend(sk_a.clone());
    let h_sk_a = blake2s_simd_params::new()
        .personal(&[0; 8])
        .to_state()
        .update(&image)
        .finalize();
    let a: u64 = q_a.amount().try_into().unwrap();
    let b: u64 = q_b.amount().try_into().unwrap();
    let c: u64 = q_c.amount().try_into().unwrap();
    let symbol: u64 = q_a.symbol().value();
    let rho_a : [u8; 32] = [2, 3, 4, 5, 6, 7, 8, 9, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32];
    let rho_c : [u8; 32] = [3, 4, 5, 6, 7, 8, 9, 10, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32];
    // Z_a
    let mut note_a = Vec::new();
    note_a.extend(a.to_le_bytes());
    note_a.extend(symbol.to_le_bytes());
    note_a.extend(rho_a.clone());
    note_a.extend(h_sk_a.as_array().clone());
    let z_a = blake2s_simd_params::new()
        .personal(&[0; 8])
        .to_state()
        .update(&note_a)
        .finalize();
    // Z_c
    let mut note_c = Vec::new();
    note_c.extend(c.to_le_bytes());
    note_c.extend(symbol.to_le_bytes());
    note_c.extend(rho_c.clone());
    note_c.extend(h_sk_a.as_array().clone());
    let z_c = blake2s_simd_params::new()
        .personal(&[0; 8])
        .to_state()
        .update(&note_c)
        .finalize();
    // N_a
    let mut nf = Vec::new();
    nf.extend(rho_a.clone());
    nf.extend(sk_a.clone());
    let nf_a = blake2s_simd_params::new()
        .personal(&[0; 8])
        .to_state()
        .update(&nf)
        .finalize();
    // auth_path (TREE_DEPTH = 2)
    //       rt
    //      /  \
    //    n1    n2
    //   /  \   /  \
    //  x   Z_a ......  
    // n1
    let mut image = Vec::new();
    let x = [0xf9, 0x85, 0xb0, 0x49, 0x6e, 0x74, 0x60, 0x4b, 0x95, 0x75, 0xdf, 0x66, 0x4a, 0x3c, 0xfd, 0x63, 0xe0, 0x62, 0xe4, 0x2a, 0xb2, 0xed, 0xa4, 0x0e, 0xdd, 0x54, 0x4d, 0x36, 0x8f, 0x7d, 0x69, 0x07];
    image.extend(x);
    image.extend(z_a.as_array().clone());
    let n1 = blake2s_simd_params::new()
        .personal(&[0; 8])
        .to_state()
        .update(&image)
        .finalize();
    //println!("{:x?}", n1.as_array());
    // rt
    let mut image = Vec::new();
    image.extend(n1.as_array().clone());
    let n2 = [0xed, 0x07, 0x6b, 0x4e, 0x3b, 0xd0, 0x14, 0xde, 0x78, 0x4a, 0xfc, 0xb8, 0x30, 0xc0, 0xa5, 0xec, 0x3b, 0x36, 0x0f, 0x50, 0x2e, 0xdf, 0x32, 0xf2, 0x67, 0x58, 0x49, 0xd7, 0xfb, 0x75, 0xc7, 0xa3];
    image.extend(n2);
    let rt = blake2s_simd_params::new()
        .personal(&[0; 8])
        .to_state()
        .update(&image)
        .finalize();
    let auth_path = [Some((x, true)), Some((n2, false))];
    /*
    // auth_path (TREE_DEPTH = 2)
    //       rt
    //      /  \
    //    n1    0
    //   /  \
    // Z_a   0
    // n1
    let mut image = Vec::new();
    image.extend(z_a.as_array().clone());
    image.extend([0; 32]);
    let n1 = blake2s_simd_params::new()
        .personal(&[0; 8])
        .to_state()
        .update(&image)
        .finalize();
    // rt
    let mut image = Vec::new();
    image.extend(n1.as_array().clone());
    image.extend([0; 32]);
    let rt = blake2s_simd_params::new()
        .personal(&[0; 8])
        .to_state()
        .update(&image)
        .finalize();
    let auth_path = [Some(([0; 32], false)), Some(([0; 32], false))];
    */
    /*
    // auth_path (TREE_DEPTH = 2)
    //       rt
    //      /  \
    //    l1    0
    //   /  \
    //  x    Z_a
    let x : [u8; 32] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32];
    // l1
    let mut image = Vec::new();
    image.extend(x.clone());
    image.extend(z_a.as_array().clone());
    let l1 = blake2s_simd_params::new()
        .personal(&[0; 8])
        .to_state()
        .update(&image)
        .finalize();
    // rt
    let mut image = Vec::new();
    image.extend(l1.as_array().clone());
    image.extend([0; 32]);
    let rt = blake2s_simd_params::new()
        .personal(&[0; 8])
        .to_state()
        .update(&image)
        .finalize();
    let auth_path = [Some((x, true)), Some(([0; 32], false))];
    //let auth_path = [Some((x, true))];
    */

    println!("Create an instance of Burn circuit (with the test values as witnesses).");
    let c = Burn {
        sk_a: Some(sk_a),
        a: Some(a),
        b: Some(b),
        c: Some(c),
        symbol: Some(symbol),
        rho_a: Some(rho_a),
        rho_c: Some(rho_c),
        auth_path: auth_path
    };
    
    
    println!("Create a Groth16 proof with our parameters.");
    let proof = groth16::create_random_proof(c, &params, &mut OsRng).unwrap();
    
    /*
    // Mint Circuit
    println!("Pack the amount, symbol and note commitment as inputs for proof verification.");
    let mut input_bits = Vec::new();
    let amount_bits = multipack::bytes_to_bits_le(&amount.to_le_bytes());
    let symbol_bits = multipack::bytes_to_bits_le(&symbol.to_le_bytes());
    let z_bits = multipack::bytes_to_bits_le(z.as_array());
    input_bits.extend(amount_bits);
    input_bits.extend(symbol_bits);
    input_bits.extend(z_bits);
    let inputs = multipack::compute_multipacking(&input_bits);
    // print proof, quantity and z_a as json
    println!("{}", to_json(&proof));
    println!("{}", quantity.to_string());
    println!("{}", to_json(&z));
    */
    /*
    // Transfer Circuit
    println!("Pack the hash as inputs for proof verification.");
    let nf_a_bits = multipack::bytes_to_bits_le(nf_a.as_array());
    let z_b_bits = multipack::bytes_to_bits_le(z_b.as_array());
    let z_c_bits = multipack::bytes_to_bits_le(z_c.as_array());
    let rt_bits = multipack::bytes_to_bits_le(rt.as_array());
    let mut input_bits = Vec::new();
    input_bits.extend(nf_a_bits.clone());
    input_bits.extend(z_b_bits.clone());
    input_bits.extend(z_c_bits.clone());
    input_bits.extend(rt_bits.clone());
    let inputs = multipack::compute_multipacking(&input_bits);
    // print proof, nullifier of a, not commitments z_b and z_c and root as json
    println!("{}", to_json(&proof));
    println!("{}", to_json(&nf_a));
    println!("{}", to_json(&z_b));
    println!("{}", to_json(&z_c));
    println!("{}", to_json(&rt));
    */
    
    // Burn Circuit
    println!("Pack the hash as inputs for proof verification.");
    let nf_a_bits = multipack::bytes_to_bits_le(nf_a.as_array());
    let b_bits = multipack::bytes_to_bits_le(&b.to_le_bytes()[..]);
    let symbol_bits = multipack::bytes_to_bits_le(&symbol.to_le_bytes()[..]);
    let z_c_bits = multipack::bytes_to_bits_le(z_c.as_array());
    let rt_bits = multipack::bytes_to_bits_le(rt.as_array());
    let mut input_bits = Vec::new();
    input_bits.extend(nf_a_bits.clone());
    input_bits.extend(b_bits.clone());
    input_bits.extend(symbol_bits.clone());
    input_bits.extend(z_c_bits.clone());
    input_bits.extend(rt_bits.clone());
    let inputs = multipack::compute_multipacking(&input_bits);
    // print proof, nullifier of a, not commitments z_b and z_c and root as json
    println!("{}", to_json(&proof));
    println!("{}", to_json(&nf_a));
    println!("{}", q_b.to_string());
    println!("{}", to_json(&z_c));
    println!("{}", to_json(&rt));
    

    // print vk as json
    //println!("{}", to_json(&params.vk));
    //println!("{}", to_json(&proof));
    //println!("{}", to_json(&inputs));

    println!("Check the proof!");
    assert!(groth16::verify_proof(&pvk, &proof, &inputs).is_ok());
/*
    let t = blake2s_simd_params::new()
        .personal(&[0; 8])
        .to_state()
        .update(b"hello world")
        .finalize();
    
    println!("{:?}", t);
    println!("{}", to_json(&t));

    let a = Asset::new(100010, Symbol::new(4, "ZEOS".to_string()));
    println!("{}", to_json(&a));
*/
}
