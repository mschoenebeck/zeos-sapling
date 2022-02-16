/**
 * Own example for blake2s proof
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
    groth16, Circuit, ConstraintSystem, SynthesisError,
};

use bls12_381::Bls12;
use ff::PrimeField;
//use pairing::{Engine, Field};
use rand::rngs::OsRng;

use blake2s_simd::{blake2s as blake2s_simd, Params as blake2s_simd_params};

extern crate rustzeos;
use rustzeos::{KeyPair, Symbol, Note, to_json};

use std::fs;
use std::any::type_name;
fn print_type_of<T>(_: &T) {
    println!("{}", std::any::type_name::<T>())
}

////
// https://stackoverflow.com/questions/52987181/how-can-i-convert-a-hex-string-to-a-u8-slice
use std::{fmt::Write, num::ParseIntError};
pub fn decode_hex(s: &str) -> Result<Vec<u8>, ParseIntError> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect()
}
pub fn encode_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        write!(&mut s, "{:02x}", b).unwrap();
    }
    s
}
////


pub struct MyCircuit {
    /// The input to SHA-256d we are proving that we know. Set to `None` when we
    /// are verifying a proof (and do not have the witness data).
    preimage: Option<[u8; 80]>,
}

//impl<Scalar: PrimeField> Circuit<Scalar> for MyCircuit {
//    fn synthesize<CS: ConstraintSystem<Scalar>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
//impl<E: Engine> Circuit<E> for MyCircuit {
//    fn synthesize<CS: ConstraintSystem<E>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
impl Circuit<bls12_381::Scalar> for MyCircuit {
    fn synthesize<CS: ConstraintSystem<bls12_381::Scalar>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        // Compute the values for the bits of the preimage. If we are verifying a proof,
        // we still need to create the same constraints, so we return an equivalent-size
        // Vec of None (indicating that the value of each bit is unknown).
        let bit_values = if let Some(preimage) = self.preimage {
            preimage
                .into_iter()
                .map(|byte| (0..8).map(move |i| (byte >> i) & 1u8 == 1u8))
                .flatten()
                .map(|b| Some(b))
                .collect()
        } else {
            vec![None; 80 * 8]
        };
        assert_eq!(bit_values.len(), 80 * 8);

        // Witness the bits of the preimage.
        let preimage_bits = bit_values
            .into_iter()
            .enumerate()
            // Allocate each bit.
            .map(|(i, b)| {
                AllocatedBit::alloc(cs.namespace(|| format!("preimage bit {}", i)), b)
            })
            // Convert the AllocatedBits into Booleans (required for the blake2s gadget).
            .map(|b| b.map(Boolean::from))
            .collect::<Result<Vec<_>, _>>()?;

        // Compute hash = SHA-256d(preimage).
        let hash = blake2s_gadget(cs.namespace(|| "blake2s(preimage)"), &preimage_bits, b"Shaftoes")?;

        // Expose the vector of 32 boolean variables as compact public inputs.
        multipack::pack_into_inputs(cs.namespace(|| "pack hash"), &hash)
    }
}

use std::fs::File;
use std::io::{BufWriter, BufReader};

fn main()
{
/*    
    // generate random params
    println!("Create parameters for our circuit. In a production deployment these would be generated securely using a multiparty computation.");
    let params = {
        let c = MyCircuit { preimage: None };
        groth16::generate_random_parameters::<Bls12, _, _>(c, &mut OsRng).unwrap()
    };
*/    
    
    /*
    // write params to file
    let params_file = File::create("params").unwrap();
    let mut params_file = BufWriter::with_capacity(1024 * 1024, params_file);
    params.write(&mut params_file).unwrap();
    */
    /*
    // read params from file
    let params_file = File::open("params").expect("couldn't open `./params`");
    let reader = BufReader::with_capacity(1024*1024, params_file);
    let mut params: groth16::Parameters<Bls12> = Parameters::read(reader, false).unwrap();
    */
    
    /*
    // write vk to file
    let vk_file = File::create("vk").unwrap();
    let mut vk_file = BufWriter::with_capacity(1024 * 1024, vk_file);
    params.vk.write(&mut vk_file).unwrap();
    */
    /*
    // read vk from file
    let vk_file = File::open("vk").expect("couldn't open `./vk`");
    let reader = BufReader::with_capacity(1024*1024, vk_file);
    let vk: groth16::VerifyingKey<Bls12> = VerifyingKey::read(reader).unwrap();
    */
    /*
    // write vk as base64 string to file
    let json = serde_json::to_string(&vk).unwrap();
    let base64str = base64::encode(&json);
    fs::write("vk.txt", base64str).expect("Unable to write file");
    */
    
    // read vk as base64 string from file
    //let base64str = fs::read_to_string("vk.txt").expect("Unable to read file");
    //let json = String::from_utf8(base64::decode(base64str).unwrap()).unwrap();
    //let vk: groth16::VerifyingKey<Bls12> = serde_json::from_str(&json).unwrap();
    //println!("vk = {:?}", vk);
/*    
    println!("Prepare the verification key (for proof verification).");
    let pvk = groth16::prepare_verifying_key(&params.vk);
    //println!("pvk = {:?}", pvk);
*/
    
    println!("Pick a preimage and compute its hash.");
    let preimage = [42; 80];
    let hash = blake2s_simd_params::new()   // https://github.com/oconnor663/blake2_simd/blob/master/blake2s/README.md
        .personal(b"Shaftoes")              // https://docs.rs/blake2s_simd/0.5.11/blake2s_simd/
        .to_state()
        .update(&preimage)
        .finalize();
    println!("{:?}", hash);

    println!("Create an instance of our circuit (with the preimage as a witness).");
    let c = MyCircuit {
        preimage: Some(preimage),
    };
    
/*    
    println!("Create a Groth16 proof with our parameters.");
    let proof = groth16::create_random_proof(c, &params, &mut OsRng).unwrap();
*/    
    /*
    // write proof to file
    let proof_file = File::create("proof").unwrap();
    let mut proof_file = BufWriter::with_capacity(1024 * 1024, proof_file);
    proof.write(&mut proof_file).unwrap();
    */
    /*
    // read proof from file
    let proof_file = File::open("proof").expect("couldn't open `./proof`");
    let reader = BufReader::with_capacity(1024*1024, proof_file);
    let proof = Proof::read(reader).unwrap();
    */
    /*
    // write proof as base64 string to file
    let json = serde_json::to_string(&proof).unwrap();
    let base64str = base64::encode(&json);
    fs::write("proof.txt", base64str).expect("Unable to write file");
    */
    
    // read proof as base64 string from file
    //let base64str = fs::read_to_string("proof.txt").expect("Unable to read file");
    //let json = String::from_utf8(base64::decode(base64str).unwrap()).unwrap();
    //let proof: groth16::Proof<Bls12> = serde_json::from_str(&json).unwrap();
    //println!("proof = {:?}", proof);
    
    println!("Pack the hash as inputs for proof verification.");
    let hash_bits = multipack::bytes_to_bits_le(&decode_hex(&hash.to_hex()).unwrap());
    let inputs: Vec<bls12_381::Scalar> = multipack::compute_multipacking(&hash_bits);

    /*
    // write inputs as base64 string to file
    let json = serde_json::to_string(&inputs).unwrap();
    let base64str = base64::encode(&json);
    fs::write("inputs.txt", base64str).expect("Unable to write file");
    */
    
    // read inputs as base64 string from file
    //let base64str = fs::read_to_string("inputs.txt").expect("Unable to read file");
    //let json = String::from_utf8(base64::decScalarode(base64str).unwrap()).unwrap();
    //let inputs: Vec<bls12_381::scalar::Scalar> = serde_json::from_str(&json).unwrap();
    //println!("inputs = {:?}", inputs);

    // write inputs as base64 string to file
    //let json = serde_json::to_string(&inputs).unwrap();
    //let base64str = base64::encode(&json);
    //fs::write("inputs_json_test.txt", json).expect("Unable to write file");

//    println!("{:?}", rustzeos::to_json(&params.vk));
//    println!("{:?}", rustzeos::to_json(&proof));
    println!("{:?}", rustzeos::to_json(&inputs));

    println!("Check the proof!");
//    assert!(groth16::verify_proof(&pvk, &proof, &inputs).is_ok());
}
