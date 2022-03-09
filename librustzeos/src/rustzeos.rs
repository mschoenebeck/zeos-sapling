use std::convert::TryInto;
use std::fmt::Write;

use bellman::{
    groth16::{
        Parameters,
        VerifyingKey,
        Proof
    },
    groth16, Circuit, ConstraintSystem, SynthesisError, multiexp::SourceBuilder,
};
use bls12_381::{Bls12};
use zeos_proofs::circuit::zeos::{NoteValue, Transfer};

use serde::{Serialize, Deserialize};
use serde::de::DeserializeOwned;
use serde_json;

use rand_core::OsRng;
use x25519_dalek::{EphemeralSecret, PublicKey};
use curve25519_dalek::scalar::Scalar as curve25519Scalar;

use aes::{Aes256, Block, ParBlocks};
use aes::cipher::{
    BlockCipher, BlockEncrypt, BlockDecrypt, NewBlockCipher,
    generic_array::GenericArray,
};

use blake2s_simd::{Hash, blake2s as blake2s_simd, Params as blake2s_simd_params};



use wasm_bindgen::prelude::*;

// returns the type name of a variable
fn type_of<T>(_: &T) -> &'static str
{
    std::any::type_name::<T>()
}


// a Secret/Private Key
pub struct SecretKey
{
    sk: curve25519Scalar
}

impl SecretKey
{
    pub fn new(mut scalar: [u8; 32]) -> SecretKey
    {
        // perform the so called "clamping"
        scalar[0] &= 248;
        scalar[31] &= 127;
        scalar[31] |= 64;

        let esk_scalar = curve25519Scalar::from_bits(scalar);
        return SecretKey{sk: esk_scalar};
    }

    pub fn new_rnd() -> SecretKey
    {
        let esk = EphemeralSecret::new(OsRng);
        let esk_scalar: &curve25519Scalar = unsafe {&*(&esk as *const EphemeralSecret as *const curve25519Scalar)};
        return SecretKey{sk: *esk_scalar};
    }

    pub fn sk(&self) -> [u8; 32]
    {
        return self.sk.to_bytes();
    }

    pub fn pk(&self) -> [u8; 32]
    {
        let esk: &EphemeralSecret = unsafe {&*(&self.sk as *const curve25519Scalar as *const EphemeralSecret)};
        let pk = PublicKey::from(esk);
        return pk.to_bytes();
    }

    pub fn h_sk(&self) -> [u8; 32]
    {
        let h_sk = blake2s_simd_params::new()
            .personal(b"Shaftoes")
            .to_state()
            .update(&self.sk.to_bytes())
            .finalize();
        return *h_sk.as_array();
    }
/*
    pub fn write_addr(&self, arr: &mut [u8; 64])
    {
        for(i, x) in self.pk.to_bytes().iter().enumerate()
        {
            arr[i] = *x;
        }
        for(i, x) in self.h_sk.as_array().iter().enumerate()
        {
            arr[32+i] = *x;
        }
    }
*/
}

// A Symbol represents an EOSIO symbol which is an unsigned 64 bit integer
#[derive(Serialize, Deserialize, Debug)]
pub struct Symbol(u64);

impl Symbol
{
    pub fn new(decimals: u8, str: String) -> Symbol
    {
        let mut res = decimals as u64;

        for(i, c) in str.chars().enumerate()
        {
            res |= (c as u64) << (8*(1+i));
        }
    
        return Symbol(res);
    }

    pub fn value(&self) -> u64
    {
        return self.0;
    }

    pub fn decimals(&self) -> u8
    {
        return (self.0 & 0xFF) as u8;
    }

    pub fn precision(&self) -> u64
    {
        let mut p10: u64 = 1;
        let mut p = self.decimals();
        while p > 0
        {
            p10 *= 10;
            p -= 1;
        }
        return p10;
    }

    pub fn name(&self) -> String
    {
        let mut v = self.0;
        v >>= 8;
        let mut res = String::from("");
        while v > 0
        {
            let c: char = (v as u8 & 0xFF) as char;
            res.push(c);
            v >>= 8;
        }
        return res;
    }
}

// This represents an EOSIO asset. 
#[derive(Serialize, Deserialize, Debug)]
pub struct Asset
{
    amount: i64,
    symbol: Symbol
}

impl Asset
{
    pub fn new(amount: i64, symbol: Symbol) -> Asset
    {
        return Asset{amount, symbol};
    }

    pub fn amount(&self) -> i64
    {
        return self.amount;
    }

    pub fn symbol(&self) -> &Symbol
    {
        return &self.symbol;
    }

    pub fn to_string(&self) -> String
    {
        let sign = if self.amount < 0 { "-" } else { "" };
        let abs_amount: u64 = self.amount.abs().try_into().unwrap();
        let mut result = (abs_amount / self.symbol.precision()).to_string();
        if self.symbol.decimals() > 0
        {
            let fract = abs_amount % self.symbol.precision();
            let mut str = (self.symbol.precision() + fract).to_string();
            str.remove(0);
            result += &(".".to_owned() + &str);
        }
        return sign.to_owned() + &result + " " + &self.symbol.name();
    }
}

impl From<&str> for Asset
{
    fn from(str: &str) -> Asset
    {
        let dot = str.find(".").unwrap();   // TODO: whta if None?
        let space = str.find(" ").unwrap();

        let decimals = space - dot - 1;
        let sbl = Symbol::new(decimals.try_into().unwrap(), str.chars().skip(space+1).collect());
        let amt = str.replace(".", "").chars().take(space-1).collect::<String>().parse::<i64>().unwrap();

        return Asset{amount: amt, symbol: sbl};
    }
}

// This represents a note. 
#[derive(Serialize, Deserialize, Debug)]
pub struct Note
{
    quantity: Asset,
    rho: [u8; 32]
}

impl Note
{
    pub fn new(quantity: Asset, rho: [u8; 32]) -> Note
    {
        return Note{quantity, rho};
    }

    pub fn amount(&self) -> i64
    {
        return self.quantity.amount();
    }

    pub fn symbol(&self) -> &Symbol
    {
        return &self.quantity.symbol();
    }

    pub fn rho(&self) -> [u8; 32]
    {
        return self.rho;
    }

    pub fn commitment(&self, h_sk: [u8; 32]) -> Hash
    {
        let mut note = Vec::new();
        note.extend(self.quantity.amount.to_le_bytes());
        note.extend(self.quantity.symbol.0.to_le_bytes());
        note.extend(self.rho);
        note.extend(h_sk);
        let commitment = blake2s_simd_params::new()
            .personal(&[0; 8])
            .to_state()
            .update(&note)
            .finalize();
        return commitment;
    }

    pub fn nullifier(&self, sk: [u8; 32]) -> Hash
    {
        let mut nf = Vec::new();
        nf.extend(self.rho);
        nf.extend(sk);
        let nullifier = blake2s_simd_params::new()
            .personal(&[0; 8])
            .to_state()
            .update(&nf)
            .finalize();
        return nullifier;
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TxReceiver
{
    pub notes: Vec<Note>,
    pub memo: [u8; 32]
}
#[derive(Serialize, Deserialize, Debug)]
pub struct TxSender
{
    pub change: Note,
    pub esk_r: [u8; 32],
    pub h_sk_r: [u8; 32],
    pub pk_r: [u8; 32]
}
#[derive(Serialize, Deserialize, Debug)]
pub struct Transaction
{
    pub epk_s: [u8; 32],
    pub sender: TxSender,
    pub epk_r: [u8; 32],
    pub receiver: TxReceiver
}
#[derive(Serialize, Deserialize, Debug)]
// this is how it looks like on the smart contract side
pub struct EncryptedTransaction
{
    pub epk_s: [u8; 32],
    pub ciphertext_s: Vec<[u8; 16]>,
    pub epk_r: [u8; 32],
    pub ciphertext_r: Vec<[u8; 16]>
}

// encrypt serializable object
pub fn encrypt_serde_object<T: Serialize + DeserializeOwned>(key: &[u8; 32], obj: &T) -> Vec<[u8; 16]>
{
    let cipher = Aes256::new(GenericArray::from_slice(key));
 
    // serialize to byte vector
    let mut ser: Vec<u8> = bincode::serialize(&obj).unwrap();

    // add 7 zero bytes . 1 byte (num of padding bytes) . padding bytes . ser
    let num_padding_bytes = 16-(ser.len()+8)%16;
    let mut ciphertext: Vec<u8> = vec![0, 0, 0, 0, 0, 0, 0, num_padding_bytes as u8];
    let mut padding_bytes = vec![0 as u8; num_padding_bytes];
    ciphertext.append(&mut padding_bytes);
    ciphertext.append(&mut ser);

    // ASSERT ciphertext.len()%16 == 0

    // encrypt to vector of aes blocks
    let mut res =Vec::new();
    let num_blocks = ciphertext.len()/16;
    for i in 0..num_blocks
    {
        let mut block = Block::clone_from_slice(&ciphertext[i*16..(i+1)*16]);

        cipher.encrypt_block(&mut block);
        let mut x = [0 as u8; 16];
        for j in 0..16
        {
            x[j] = block[j];
        }
        res.push(x);
    }

    return res;
}

// decrypt serializable object
pub fn decrypt_serde_object<T: Serialize + DeserializeOwned>(key: &[u8; 32], aes_blocks: &Vec<[u8; 16]>) -> T
{
    let cipher = Aes256::new(GenericArray::from_slice(key));

    // decrypt vector of aes blocks
    let mut ciphertext: Vec<u8> = vec![];
    for i in 0..aes_blocks.len()
    {
        let mut block = Block::clone_from_slice(&aes_blocks[i]);
        //println!("{:?}", block);

        cipher.decrypt_block(&mut block);
        for j in 0..16
        {
            ciphertext.push(block[j]);
        }
    }

    // check for 7 null bytes
    for i in 0..7
    {
        if 0 != ciphertext[i]
        {
            println!("error!");
        }
    }
    let num_padding_bytes = ciphertext[7];
    // cut off the padding bytes
    let l: usize = (8+num_padding_bytes) as usize;
    let mut ser = vec![0; ciphertext.len()-l];
    ser.clone_from_slice(&ciphertext[l..ciphertext.len()]);

    let de: T = bincode::deserialize(&ser[..]).unwrap();

    return de;
}

// to smart contract json function (VK, Proof, Inputs)
pub fn to_json<T>(var: &T) -> String
{
    // struct definitions
    pub struct Choice(pub u8);
    pub struct Fp(pub [u64; 6]);
    pub struct Scalar(pub [u64; 4]);
    pub struct Fp2
    {
        pub c0: Fp,
        pub c1: Fp,
    }
    pub struct G1Affine
    {
        pub x: Fp,
        pub y: Fp,
        pub infinity: Choice,
    }
    pub struct G2Affine
    {
        pub x: Fp2,
        pub y: Fp2,
        pub infinity: Choice,
    }

    let mut json = String::new();

    match type_of(var)
    {
        "bellman::groth16::VerifyingKey<bls12_381::pairings::Bls12>" =>
        {
            json.push('{');

            let vk: &VerifyingKey<Bls12> = unsafe {&*(var as *const T as *const VerifyingKey<Bls12>)};
               
            json.push_str("\"alpha_g1\":");
            json.push_str(to_json(&vk.alpha_g1).as_str());
            json.push(',');
               
            json.push_str("\"beta_g1\":");
            json.push_str(to_json(&vk.beta_g1).as_str());
            json.push(',');
               
            json.push_str("\"beta_g2\":");
            json.push_str(to_json(&vk.beta_g2).as_str());
            json.push(',');
               
            json.push_str("\"gamma_g2\":");
            json.push_str(to_json(&vk.gamma_g2).as_str());
            json.push(',');
               
            json.push_str("\"delta_g1\":");
            json.push_str(to_json(&vk.delta_g1).as_str());
            json.push(',');
               
            json.push_str("\"delta_g2\":");
            json.push_str(to_json(&vk.delta_g2).as_str());
            json.push(',');
               
            json.push_str("\"ic\":");
            json.push_str(to_json(&vk.ic).as_str());
            
            json.push('}');
        },
        "bellman::groth16::Proof<bls12_381::pairings::Bls12>" =>
        {
            json.push('{');

            let proof: &Proof<Bls12> = unsafe {&*(var as *const T as *const Proof<Bls12>)};
               
            json.push_str("\"a\":");
            json.push_str(to_json(&proof.a).as_str());
            json.push(',');
               
            json.push_str("\"b\":");
            json.push_str(to_json(&proof.b).as_str());
            json.push(',');
               
            json.push_str("\"c\":");
            json.push_str(to_json(&proof.c).as_str());
            
            json.push('}');
        },
        "rustzeos::to_json::G1Affine" |
        "bls12_381::g1::G1Affine" =>
        {
            json.push('{');

            let g1: &G1Affine = unsafe {&*(var as *const T as *const G1Affine)};
               
            json.push_str("\"x\":");
            json.push_str(to_json(&g1.x).as_str());
            json.push(',');
               
            json.push_str("\"y\":");
            json.push_str(to_json(&g1.y).as_str());
            json.push(',');
               
            json.push_str("\"infinity\":");
            json.push_str(to_json(&g1.infinity).as_str());
            
            json.push('}');
        },
        "rustzeos::to_json::G2Affine" |
        "bls12_381::g2::G2Affine" =>
        {
            json.push('{');

            let g2: &G2Affine = unsafe {&*(var as *const T as *const G2Affine)};
               
            json.push_str("\"x\":");
            json.push_str(to_json(&g2.x).as_str());
            json.push(',');
               
            json.push_str("\"y\":");
            json.push_str(to_json(&g2.y).as_str());
            json.push(',');
               
            json.push_str("\"infinity\":");
            json.push_str(to_json(&g2.infinity).as_str());
            
            json.push('}');
        },
        "alloc::vec::Vec<bls12_381::g1::G1Affine>" =>
        {
            json.push('[');

            let vec: &Vec<G1Affine> = unsafe {&*(var as *const T as *const Vec<G1Affine>)};

            for v in vec
            {
                json.push_str(to_json(v).as_str());
                json.push(',');
            }
            json.pop();

            json.push(']');
        },
        "alloc::vec::Vec<bls12_381::scalar::Scalar>" =>
        {
            json.push('[');

            let vec: &Vec<Scalar> = unsafe {&*(var as *const T as *const Vec<Scalar>)};

            for v in vec
            {
                json.push_str(to_json(v).as_str());
                json.push(',');
            }
            json.pop();

            json.push(']');
        },
        "rustzeos::to_json::Fp" => 
        {
            json.push_str("{\"data\":[");
            
            let fp: &Fp = unsafe {&*(var as *const T as *const Fp)};

            for v in fp.0
            {
                json.push_str(format!("{}", v).as_str());
                json.push(',');
            }
            json.pop();

            json.push_str("]}");
        },
        "rustzeos::to_json::Scalar" => 
        {
            json.push_str("{\"data\":[");
            
            let scalar: &Scalar = unsafe {&*(var as *const T as *const Scalar)};

            for v in scalar.0
            {
                json.push_str(format!("{}", v).as_str());
                json.push(',');
            }
            json.pop();

            json.push_str("]}");
        },
        "rustzeos::to_json::Fp2" => 
        {
            json.push('{');

            let fp2: &Fp2 = unsafe {&*(var as *const T as *const Fp2)};
               
            json.push_str("\"c0\":");
            json.push_str(to_json(&fp2.c0).as_str());
            json.push(',');
               
            json.push_str("\"c1\":");
            json.push_str(to_json(&fp2.c1).as_str());
            
            json.push('}');
        },
        "rustzeos::to_json::Choice" =>
        {
            json.push_str("{\"data\":");
            
            let c: &Choice = unsafe {&*(var as *const T as *const Choice)};
            
            json.push_str(format!("{}", c.0).as_str());
            
            json.push('}');
        },
        "blake2s_simd::Hash" =>
        {
            let h: &Hash = unsafe {&*(var as *const T as *const Hash)};
            
            for byte in h.as_array()
            {
                json.push_str(format!("{:02x}", byte).as_str());
            }
        },
        "rustzeos::Asset" =>
        {
            let a: &Asset = unsafe {&*(var as *const T as *const Asset)};
            
            json.push_str(format!("{}", a.to_string()).as_str());
        },
        _ =>
        {
            json.push_str("ERROR: unknown type: ");
            json.push_str(type_of(var));
        }
    }

    return json;
}

// generate mint transaction
#[wasm_bindgen]
#[allow(non_snake_case)]
#[no_mangle]
pub fn generate_mint_transaction(params_bytes: &[u8], secret_key: &[u8], tx_str: String) -> String
{
    // read Parameter from byte array from JS like this: https://stackoverflow.com/questions/56685410/pass-file-from-javascript-to-u8-in-rust-webassembly
    //let params: groth16::Parameters<Bls12> = Parameters::read(params_bytes, false).unwrap();
    
    let sk: &SecretKey = unsafe {&*(secret_key as *const [u8] as *const SecretKey)};

    let tx: Transaction = serde_json::from_str(&tx_str).unwrap();

    // circuit struct
    // proof erzeugen
    // als json zurueckgeben
    return format!("tx.sender.change.amt = {:?}, tx.receiver.notes[1].amt = {:?}, sk = {:x?}", tx.sender.change.amount(), tx.receiver.notes[1].amount(), sk.sk());
    //return to_json(&params.vk);
    //return "hello ".into();
}

// decrypt transaction
#[wasm_bindgen]
#[allow(non_snake_case)]
#[no_mangle]
pub fn decrypt_transaction(secret_key: &[u8], encrypted_transaction: String) -> String
{
    let sk: &SecretKey = unsafe {&*(secret_key as *const [u8] as *const SecretKey)};
    let enc_tx: EncryptedTransaction = serde_json::from_str(&encrypted_transaction).unwrap();

    // decrypt

    return format!("enc_tx.ciphertext_s[2] = {:x?}, sk = {:x?}", enc_tx.ciphertext_s[2], sk.sk());
}

// test function
#[no_mangle]
pub extern "C" fn rust_function(a: i32, b: i32) -> i32
{
    return a + b;
}

#[wasm_bindgen]
extern {
    pub fn alert(s: &str);
}

#[wasm_bindgen]
pub fn greet(name: &str) {
    alert(&format!("Hello, {}!", name));
}

