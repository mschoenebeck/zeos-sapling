

use rand_core::OsRng;
use x25519_dalek::{EphemeralSecret, PublicKey};
use curve25519_dalek::scalar::Scalar;

use aes::{Aes256, Block, ParBlocks};
use aes::cipher::{
    BlockCipher, BlockEncrypt, BlockDecrypt, NewBlockCipher,
    generic_array::GenericArray,
};

fn main()
{
    // Alice creates key pair
    let alice_secret = EphemeralSecret::new(OsRng);
    let alice_public = PublicKey::from(&alice_secret);
    
    let w = &alice_secret as *const EphemeralSecret as *const curve25519_dalek::scalar::Scalar;
    let alice_secret_scalar: &curve25519_dalek::scalar::Scalar = unsafe {&*w};

    println!("alice sk = {:02x?}", alice_secret_scalar.to_bytes());
    println!("alice pk = {:02x?}", alice_public.to_bytes());

    // Bob creates key pair
    let bob_secret = EphemeralSecret::new(OsRng);
    let bob_public = PublicKey::from(&bob_secret);

    let w = &bob_secret as *const EphemeralSecret as *const curve25519_dalek::scalar::Scalar;
    let bob_secret_scalar: &curve25519_dalek::scalar::Scalar = unsafe {&*w};

    println!("bob sk   = {:02x?}", bob_secret_scalar.to_bytes());
    println!("bob pk   = {:02x?}", bob_public.to_bytes());

    // Alice and Bob perform Diffie Hellman exchange
    let alice_shared_secret = alice_secret.diffie_hellman(&bob_public);
    let bob_shared_secret = bob_secret.diffie_hellman(&alice_public);

    // Each peer's computed shared secret should be the same.
    assert_eq!(alice_shared_secret.as_bytes(), bob_shared_secret.as_bytes());
    println!("alice shared secret = {:02x?}", alice_shared_secret.to_bytes());
    println!("bob shared secret   = {:02x?}", bob_shared_secret.to_bytes());

    // AES encryption
    let mut block = Block::default();
    let mut block8 = ParBlocks::default();
    
    let key = GenericArray::from_slice(alice_shared_secret.as_bytes());
    let cipher = Aes256::new(&key);

    let block_copy = block.clone();

    println!("unencrypted block = {:?}", block);
    // Encrypt block in-place
    cipher.encrypt_block(&mut block);
    println!("  encrypted block = {:?}", block);
    // And decrypt it back
    cipher.decrypt_block(&mut block);
    assert_eq!(block, block_copy);
    println!("  decrypted block = {:?}", block);

    // We can encrypt 8 blocks simultaneously using
    // instruction-level parallelism
    let block8_copy = block8.clone();
    cipher.encrypt_par_blocks(&mut block8);
    cipher.decrypt_par_blocks(&mut block8);
    assert_eq!(block8, block8_copy);
}

