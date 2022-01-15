
//use bellman::{groth16::{VerifyingKey, Proof}, groth16};
//use bls12_381::{Bls12};

//extern crate libc;
//use libc::{c_char, puts};
//use std::ffi::CStr;

#[no_mangle]
//pub extern "C" fn verify_proof(vk_cstr: *const c_char, proof_cstr: *const c_char, inputs_cstr: *const c_char) -> bool
pub extern "C" fn verify_proof() -> bool
{
/*
    // convert the C strings to rust strings
    let vk_str = unsafe {
        assert!(!vk_cstr.is_null());
        CStr::from_ptr(vk_cstr).to_str().unwrap()
    };
    let proof_str = unsafe {
        assert!(!proof_cstr.is_null());
        CStr::from_ptr(proof_cstr).to_str().unwrap()
    };
    let inputs_str = unsafe {
        assert!(!inputs_cstr.is_null());
        CStr::from_ptr(inputs_cstr).to_str().unwrap()
    };
*/

    //let vk: VerifyingKey<Bls12> = VerifyingKey{alpha_g1: G1Affine{x: Fp([0u64; 6]), y: 0, infinity: 0}, beta_g1: G1Affine{}, beta_g2: G2Affine{}};
    //let vk: VerifyingKey<Bls12> = VerifyingKey{..Default::default()};
    //let proof: Proof<Bls12> = Proof{..Default::default()};
    //let inputs: Vec<bls12_381::scalar::Scalar> = Default::default();
/*
    // reconstruct verifier key from base64 encoded string
    let json = String::from_utf8(base64::decode(vk_str).unwrap()).unwrap();
    let vk: VerifyingKey<Bls12> = serde_json::from_str(&json).unwrap();
    // reconstruct proof from base64 encoded string
    let json = String::from_utf8(base64::decode(proof_str).unwrap()).unwrap();
    let proof: Proof<Bls12> = serde_json::from_str(&json).unwrap();
    // reconstruct public inputs for the proof from base64 encoded string
    let json = String::from_utf8(base64::decode(inputs_str).unwrap()).unwrap();
    let inputs: Vec<bls12_381::scalar::Scalar> = serde_json::from_str(&json).unwrap();
*/
    // prepare verifying key (TODO: shouldn't happen here but earlier when added to contract)     
//    let pvk = groth16::prepare_verifying_key(&vk);
    
    // check if proof is valid
//    return groth16::verify_proof(&pvk, &proof, &inputs).is_ok();
    //return vk.alpha_g1.x.0[0] == 0;
    return false;
}

/*
// test function
#[no_mangle]
pub extern "C" fn rust_function2(str1: *const c_char, str2: *const c_char) -> i32
{
    let str1 = unsafe {
        assert!(!str1.is_null());
        CStr::from_ptr(str1).to_str().unwrap()
    };
    let str2 = unsafe {
        assert!(!str2.is_null());
        CStr::from_ptr(str2).to_str().unwrap()
    };
    
    let together = format!("{}{}", str1.to_owned(), str2.to_owned());
    
    return unsafe {
        puts(together.as_ptr() as *const c_char)
    };
    
}
*/
// test function
#[no_mangle]
pub extern "C" fn rust_function(a: i32, b: i32) -> i32
{
    return a + b;
}

