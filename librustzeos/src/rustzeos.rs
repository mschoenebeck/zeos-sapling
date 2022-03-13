

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
use zeos_proofs::circuit::zeos::{Mint, Transfer, Burn, TREE_DEPTH};

use serde::{Serialize, Deserialize};
use serde::de::DeserializeOwned;
use serde_json;

use x25519_dalek::{StaticSecret, PublicKey};

use rand::rngs::OsRng;

use aes::{Aes256, Block, ParBlocks};
use aes::cipher::{
    BlockCipher, BlockEncrypt, BlockDecrypt, NewBlockCipher,
    generic_array::GenericArray,
};

use blake2s_simd::{Hash, blake2s as blake2s_simd, Params as blake2s_simd_params};

use wasm_bindgen::prelude::*;

// Logging using web_sys: https://rustwasm.github.io/book/reference/debugging.html
extern crate web_sys;
//web_sys::console::log_1(&"Hello, world!".into());
//web_sys::console::log takes an array of values to log
//web_sys::console::log_1 logs a single value
//web_sys::console::log_2 logs two values

// returns the type name of a variable
fn type_of<T>(_: &T) -> &'static str
{
    std::any::type_name::<T>()
}

// a Secret/Private Key
pub struct SecretKey(StaticSecret);

impl SecretKey
{
    pub fn new() -> Self
    {
        use rand::RngCore;
        let mut buf: [u8; 32] = [0; 32];
        OsRng.fill_bytes(&mut buf);
        return SecretKey(StaticSecret::from(buf));
    }

    pub fn h_sk(&self) -> [u8; 32]
    {
        let h_sk = blake2s_simd_params::new()
            .personal(&[0; 8])
            .to_state()
            .update(&self.0.to_bytes())
            .finalize();
        return *h_sk.as_array();
    }

    pub fn sk(&self) -> [u8; 32]
    {
        return self.0.to_bytes();
    }

    pub fn pk(&self) -> [u8; 32]
    {
        return PublicKey::from(&self.0).to_bytes();
    }

    pub fn addr(&self) -> Address
    {
        return Address::new(&self.h_sk(), &self.pk());
    }

    pub fn diffie_hellman(&self, pk: &[u8; 32]) -> [u8; 32]
    {
        return self.0.diffie_hellman(&PublicKey::from(*pk)).to_bytes();
    }
}
impl From<[u8; 32]> for SecretKey
{
    /// Load a secret key from a byte array.
    fn from(bytes: [u8; 32]) -> SecretKey
    {
        return SecretKey(StaticSecret::from(bytes));
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Address
{
    h_sk: [u8; 32],
    pk: [u8; 32]
}

impl Address
{
    pub fn new(h_sk: &[u8; 32], pk: &[u8; 32]) -> Self
    {
        return Address{h_sk: *h_sk, pk: *pk};
    }

    pub fn h_sk(&self) -> [u8; 32]
    {
        return self.h_sk;
    }

    pub fn pk(&self) -> [u8; 32]
    {
        return self.pk;
    }
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
    // must have format: "123.1234 SYM"
    fn from(str: &str) -> Asset
    {
        let dot = str.find(".").unwrap();
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

    pub fn quantity(&self) -> &Asset
    {
        return &self.quantity;
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
    pub esk_s: [u8; 32],    // viewing key which in combination of the senders public key is able to decrypt the whole tx. can be shared with others as proof of payment
    pub esk_r: [u8; 32],
    pub addr_r: Address
}
#[derive(Serialize, Deserialize, Debug)]
pub struct Transaction
{
    pub epk_s: [u8; 32],
    pub sender: Option<TxSender>,
    pub epk_r: [u8; 32],
    pub receiver: Option<TxReceiver>
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
// this is how JS receives the struct and passes it to this library to decrypt it
#[derive(Serialize, Deserialize, Debug)]
pub struct EncryptedTransactionJS
{
    pub epk_s: String,
    pub ciphertext_s: Vec<String>,
    pub epk_r: String,
    pub ciphertext_r: Vec<String>
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
pub fn decrypt_serde_object<T: Serialize + DeserializeOwned>(key: &[u8; 32], aes_blocks: &Vec<[u8; 16]>) -> Option<T>
{
    if 0 == aes_blocks.len()
    {
        return None;
    }

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
            return None;
        }
    }
    let num_padding_bytes = ciphertext[7];
    // cut off the padding bytes
    let l: usize = (8+num_padding_bytes) as usize;
    let mut ser = vec![0; ciphertext.len()-l];
    ser.clone_from_slice(&ciphertext[l..ciphertext.len()]);

    let de: T = bincode::deserialize(&ser[..]).unwrap();
    
    return Some(de);
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
            json.push_str(&serde_json::to_string(a).unwrap());
        },
        "rustzeos::Transaction" =>
        {
            let tx: &Transaction = unsafe {&*(var as *const T as *const Transaction)};
            json.push_str(&serde_json::to_string(tx).unwrap());
        },
        "rustzeos::EncryptedTransaction" =>
        {
            let enc_tx: &EncryptedTransaction = unsafe {&*(var as *const T as *const EncryptedTransaction)};
            json.push_str(&serde_json::to_string(enc_tx).unwrap());
        },
        "rustzeos::TxSender" =>
        {
            let txs: &TxSender = unsafe {&*(var as *const T as *const TxSender)};
            json.push_str(&serde_json::to_string(txs).unwrap());
        },
        "rustzeos::TxReceiver" =>
        {
            let txr: &TxReceiver = unsafe {&*(var as *const T as *const TxReceiver)};
            json.push_str(&serde_json::to_string(txr).unwrap());
        },
        "rustzeos::Note" =>
        {
            let n: &Note = unsafe {&*(var as *const T as *const Note)};
            json.push_str(&serde_json::to_string(n).unwrap());
        },
        "rustzeos::Symbol" =>
        {
            let s: &Symbol = unsafe {&*(var as *const T as *const Symbol)};
            json.push_str(&serde_json::to_string(s).unwrap());
        },/*
        "core::option::Option<rustzeos::TxSender>" =>
        {
            let op_txs: &Option<TxSender> = unsafe {&*(var as *const T as *const Option<TxSender>)};
            let txs = match op_txs {
                Some(ref x) => serde_json::to_string(x).unwrap(),
                None => "null".into()
            };
            json.push_str(&txs);
        },
        "core::option::Option<rustzeos::TxReceiver>" =>
        {
            let op_txr: &Option<TxReceiver> = unsafe {&*(var as *const T as *const Option<TxReceiver>)};
            let txr = match op_txr {
                Some(ref x) => serde_json::to_string(x).unwrap(),
                None => "null".into()
            };
            json.push_str(&txr);
        },*/
        "rustzeos::SecretKey" =>
        {
            let sk: &[u8; 32] = unsafe {&*(var as *const T as *const [u8; 32])};
            json.push_str(&serde_json::to_string(sk).unwrap());
        },
        "rustzeos::Address" =>
        {
            let addr: &Address = unsafe {&*(var as *const T as *const Address)};
            json.push_str(&serde_json::to_string(addr).unwrap());
        },
        "alloc::vec::Vec<[u8; 16]>" =>
        {
            let v: &Vec<[u8; 16]> = unsafe {&*(var as *const T as *const Vec<[u8; 16]>)};
            json.push_str(&serde_json::to_string(v).unwrap());
        }
        _ =>
        {
            json.push_str("ERROR: unknown type: ");
            json.push_str(type_of(var));
        }
    }

    return json;
}

// generate a new key pair
#[wasm_bindgen]
#[allow(non_snake_case)]
#[no_mangle]
pub fn create_key(seed: &[u8]) -> String
{
    // if secret_key is at least a 32 byte array it's values will be used as a seed for the new secret key
    if seed.len() >= 32
    {
        let seed: &[u8; 32] = unsafe {&*(seed as *const [u8] as *const [u8; 32])};
        let sk = SecretKey::from(*seed);
        return format!("{{\"sk\":{},\"addr\":{}}}", to_json(&sk), to_json(&sk.addr()));
    }

    // create new random key
    let sk = SecretKey::new();
    return format!("{{\"sk\":{},\"addr\":{}}}", to_json(&sk), to_json(&sk.addr()));
}

// generate mint transaction
#[wasm_bindgen]
#[allow(non_snake_case)]
#[no_mangle]
pub fn create_mint_transaction(params_bytes: &[u8], addr_json: String, tx_r_json: String, eos_username: String) -> String
{
    // read Parameter file from byte array
    let params: groth16::Parameters<Bls12> = Parameters::read(params_bytes, false).unwrap();
    
    // parse addr and tx_r object
    let addr: Address = serde_json::from_str(&addr_json).unwrap();
    let txr: TxReceiver = serde_json::from_str(&tx_r_json).unwrap();

    // create new random key pair to encrypt receiver part
    let esk_r = SecretKey::new();
    // create symmetric aes encryption key using DH
    let receiver_enc_key = esk_r.diffie_hellman(&addr.pk);

    // create encrypted tx
    let enc_tx = EncryptedTransaction{
        epk_s: [0; 32],
        ciphertext_s: Vec::new(),
        epk_r: esk_r.pk(),
        ciphertext_r: encrypt_serde_object(&receiver_enc_key, &txr)
    };

    // initialize instance of Mint circuit with private input
    let amount: u64 = txr.notes[0].amount().try_into().unwrap();
    let symbol: u64 = txr.notes[0].symbol().value();
    let rho: [u8; 32] = txr.notes[0].rho();
    let h_sk: [u8; 32] = addr.h_sk();
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

    let c = Mint {
        amount: Some(amount),
        symbol: Some(symbol),
        rho: Some(rho),
        h_sk: Some(h_sk)
    };

    // create proof
    let proof = groth16::create_random_proof(c, &params, &mut OsRng).unwrap();

    // create the EOS tx
    // see thezeostoken contract "mint" action for details about the parameter
    let mut epk_s_str = format!("{:02x?}", enc_tx.epk_s).replace(", ", "");
    epk_s_str.pop();
    epk_s_str.remove(0);
    let mut epk_r_str = format!("{:02x?}", enc_tx.epk_r).replace(", ", "");
    epk_r_str.pop();
    epk_r_str.remove(0);
    let mut enc_sender_str = String::from("[");
    for block in enc_tx.ciphertext_s.iter()
    {
        let block128u = u128::from_le_bytes(*block);
        let block_str = format!("\"{}\",", block128u);
        enc_sender_str += &block_str;
    }
    if enc_tx.ciphertext_s.len() > 0
    {
        enc_sender_str.pop(); // remove last comma
    }
    enc_sender_str += &String::from("]");


    let mut enc_receiver_str = String::from("[");
    for block in enc_tx.ciphertext_r.iter()
    {
        let block128u = u128::from_le_bytes(*block);
        let block_str = format!("\"{}\",", block128u);
        enc_receiver_str += &block_str;
    }
    if enc_tx.ciphertext_r.len() > 0
    {
        enc_receiver_str.pop(); // remove last comma
    }
    enc_receiver_str += &String::from("]");
    //web_sys::console::log_2(&"z_str: ".into(), &z_str.clone().into());


    let proof_str = to_json(&proof).replace("\"", "\\\"");
    let a_str = format!("{}", txr.notes[0].quantity.to_string());
    let mut z_str = format!("{:02X?}", z.as_bytes()).replace(", ", "");
    z_str.pop();
    z_str.remove(0);

    // put the whole EOS tx together
    return String::from(String::from(
    r#"{
        "epk_s":""#) + &epk_s_str + &String::from(r#"",
        "ciphertext_s":"#) + &enc_sender_str + &String::from(r#",
        "epk_r":""#) + &epk_r_str + &String::from(r#"",
        "ciphertext_r":"#) + &enc_receiver_str + &String::from(r#",
        "proof":""#) + &proof_str + &String::from(r#"",
        "a":""#) + &a_str + &String::from(r#"",
        "z_a":""#) + &z_str + &String::from(r#"",
        "user":""#) + &eos_username + &String::from(r#""
        }"#)).replace("\n        ", "");
}

// decrypt transaction
#[wasm_bindgen]
#[allow(non_snake_case)]
#[no_mangle]
pub fn decrypt_transaction(secret_key: &[u8], encrypted_transaction: String) -> String
{
    // obtain parameters
    let sk: &SecretKey = unsafe {&*(secret_key as *const [u8] as *const SecretKey)};
    let enc_tx_js: EncryptedTransactionJS = serde_json::from_str(&encrypted_transaction).unwrap();

    // translate JS struct to library struct
    let mut enc_tx: EncryptedTransaction = EncryptedTransaction { epk_s: [0; 32], ciphertext_s: Vec::new(), epk_r: [0; 32], ciphertext_r: Vec::new() };
    hex::decode_to_slice(enc_tx_js.epk_s, &mut enc_tx.epk_s).expect("Decoding of 'enc_tx_js.epk_s' failed");
    hex::decode_to_slice(enc_tx_js.epk_r, &mut enc_tx.epk_r).expect("Decoding of 'enc_tx_js.epk_r' failed");
    for block_str in enc_tx_js.ciphertext_s.iter()
    {
        let block128u = u128::from_str_radix(block_str, 10).unwrap();
        enc_tx.ciphertext_s.push(u128::to_le_bytes(block128u));
    }
    for block_str in enc_tx_js.ciphertext_r.iter()
    {
        let block128u = u128::from_str_radix(block_str, 10).unwrap();
        enc_tx.ciphertext_r.push(u128::to_le_bytes(block128u));
    }

    // the two parts of the transaction we try to decrypt
    let mut sender: Option<TxSender> = None;
    let mut receiver: Option<TxReceiver> = None;

    // first try the sender part: obtain symmetric aes encryption key for sender part by performing Diffie Hellman using (sk, epk_s)
    let sender_enc_key = sk.diffie_hellman(&enc_tx.epk_s);
    sender = decrypt_serde_object(&sender_enc_key, &enc_tx.ciphertext_s);
    
    match sender
    {
        // if successful then this secret key was the sender of this tx and can decrypt the whole thing
        Some(ref x) => 
        {
            let receiver_enc_key = SecretKey::from(x.esk_r).diffie_hellman(&x.addr_r.pk);
            receiver = decrypt_serde_object(&receiver_enc_key, &enc_tx.ciphertext_r);
        },

        // if sender decryption was unsuccessful try receiver part
        None => 
        {
            let receiver_enc_key = sk.diffie_hellman(&enc_tx.epk_r);
            receiver = decrypt_serde_object(&receiver_enc_key, &enc_tx.ciphertext_r);
        }
    }
    
    let tx = Transaction{
        epk_s: enc_tx.epk_s,
        sender: sender,
        epk_r: enc_tx.epk_r,
        receiver: receiver
    };

    return to_json(&tx);
}

// get note commitment
#[wasm_bindgen]
#[allow(non_snake_case)]
#[no_mangle]
pub fn note_commitment(note_json: String, h_sk: &[u8]) -> String
{
    let h_sk_ = unsafe {&*(h_sk as *const [u8] as *const [u8; 32])};
    let note: Note = serde_json::from_str(&note_json).unwrap();
    
    let mut z_n_str = format!("{:02x?}", note.commitment(*h_sk_).as_bytes()).replace(", ", "");
    z_n_str.pop();
    z_n_str.remove(0);
    
    return z_n_str;
}

// get note nullifier
#[wasm_bindgen]
#[allow(non_snake_case)]
#[no_mangle]
pub fn note_nullifier(note_json: String, sk: &[u8]) -> String
{
    let sk_ = unsafe {&*(sk as *const [u8] as *const [u8; 32])};
    let note: Note = serde_json::from_str(&note_json).unwrap();
    
    let mut n_n_str = format!("{:02x?}", note.nullifier(*sk_).as_bytes()).replace(", ", "");
    n_n_str.pop();
    n_n_str.remove(0);
    
    return n_n_str;
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
