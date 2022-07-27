
use ff::PrimeField;

use bellman::{Circuit, ConstraintSystem, LinearCombination, SynthesisError};

use bellman::gadgets::blake2s;
use bellman::gadgets::boolean;
use bellman::gadgets::multipack;

pub const TREE_DEPTH: usize = 2;



/// This is an instance of the `Mint` circuit.
pub struct Mint
{
    pub amount: Option<u64>,
    pub symbol: Option<u64>,
    pub rho: Option<[u8; 32]>,
    pub h_sk: Option<[u8; 32]>
}

impl Circuit<bls12_381::Scalar> for Mint
{
    fn synthesize<CS: ConstraintSystem<bls12_381::Scalar>>(
        self,
        cs: &mut CS,
    ) -> Result<(), SynthesisError>
    {
        // amount to boolean bit vector
        let amount_bits = boolean::u64_into_boolean_vec_le(
            cs.namespace(|| "amount"),
            self.amount
        )?;

        // symbol to boolean bit vector
        let symbol_bits = boolean::u64_into_boolean_vec_le(
            cs.namespace(|| "symbol"),
            self.symbol
        )?;
        
        // rho to boolean bit vector
        let rho_bits = boolean::u8_vec_into_boolean_vec_le(
            cs.namespace(|| "rho"),
            self.rho,
        )?;
        
        // h_sk to boolean bit vector
        let h_sk_bits = boolean::u8_vec_into_boolean_vec_le(
            cs.namespace(|| "h_sk"),
            self.h_sk,
        )?;
        
        // concatenate note = (amount | symbol | rho | h_sk) for input to hash function
        let mut note = Vec::new();
        note.extend(amount_bits.clone());
        note.extend(symbol_bits.clone());
        note.extend(rho_bits.clone());
        note.extend(h_sk_bits.clone());

        // calculate hash value: h(note)
        let z = blake2s::blake2s(cs.namespace(|| "blake2s(note)"), &note, &[0; 8])?;
        
        // expose public inputs: amount, symbol, z
        let mut inputs = vec![];
        inputs.extend(amount_bits);
        inputs.extend(symbol_bits);
        inputs.extend(z);
        
        return multipack::pack_into_inputs(cs.namespace(|| "pack inputs"), &inputs);
    }
}

/// This is an instance of the `Transfer` circuit.
pub struct Transfer
{
    // secret key to spend a
    pub sk_a: Option<[u8; 32]>,

    // value which is being spent by sk
    pub a: Option<u64>,
    // value which is received by pk
    pub b: Option<u64>,
    // the "change" that goes back to pk(sk)
    // a = b + c
    pub c: Option<u64>,

    // the symbol of the notes (only one because it must be the same for all 3 notes)
    pub symbol: Option<u64>,

    // salts for note commitments
    pub rho_a: Option<[u8; 32]>,
    pub rho_b: Option<[u8; 32]>,
    pub rho_c: Option<[u8; 32]>,

    // h_sk i.e. the address to receive 'b'
    pub h_sk_b: Option<[u8; 32]>,

    // authentication path in the merkle tree i.e. the sister path of note commitment of value 'a'
    pub auth_path: [Option<([u8; 32], bool)>; TREE_DEPTH]
}

impl Circuit<bls12_381::Scalar> for Transfer
{
    fn synthesize<CS: ConstraintSystem<bls12_381::Scalar>>(
        self,
        cs: &mut CS,
    ) -> Result<(), SynthesisError>
    {
        // calculate h_sk_a of sk_a which is defined as: h_sk_a := h(sk_a)
        // sk_a to boolean bit vector
        let sk_a_bits = boolean::u8_vec_into_boolean_vec_le(
            cs.namespace(|| "sk_a"),
            self.sk_a,
        )?;
        // boolean bit vector h_sk_a := h(sk_a)
        let h_sk_a_bits = blake2s::blake2s(cs.namespace(|| "blake2s(sk_a)"), &sk_a_bits, &[0; 8])?;

        // symbol to boolean bit vector
        let symbol_bits = boolean::u64_into_boolean_vec_le(
            cs.namespace(|| "symbol"),
            self.symbol
        )?;

        // calculate the note commitment Z_a of value 'a' which is defined as: Z_a := h(a | h_sk_a | rho_a)
        // 'a' to boolean bit vector
        let a_bits = boolean::u64_into_boolean_vec_le(
            cs.namespace(|| "a"),
            self.a
        )?;
        // rho_a to boolean bit vector
        let rho_a_bits = boolean::u8_vec_into_boolean_vec_le(
            cs.namespace(|| "rho_a"),
            self.rho_a,
        )?;
        // concatenate (a | h_sk_a | rho_a) for input to hash function
        let mut note_a = Vec::new();
        note_a.extend(a_bits.clone());
        note_a.extend(symbol_bits.clone());
        note_a.extend(rho_a_bits.clone());
        note_a.extend(h_sk_a_bits.clone());
        // boolean bit vector Z_a := h(a | h_sk_a | rho_a)
        let z_a_bits = blake2s::blake2s(cs.namespace(|| "blake2s(a | h_sk_a | rho_a)"), &note_a, &[0; 8])?;

        // calculate the note commitment Z_b of value 'b' which is defined as: Z_b := h(b | h_sk_b | rho_b)
        // 'b' to boolean bit vector
        let b_bits = boolean::u64_into_boolean_vec_le(
            cs.namespace(|| "b"),
            self.b
        )?;
        // rho_b to boolean bit vector
        let rho_b_bits = boolean::u8_vec_into_boolean_vec_le(
            cs.namespace(|| "rho_b"),
            self.rho_b,
        )?;
        // h_sk_b to boolean bit vector
        let h_sk_b_bits = boolean::u8_vec_into_boolean_vec_le(
            cs.namespace(|| "h_sk_b"),
            self.h_sk_b,
        )?;
        // concatenate (b | h_sk_b | rho_b) for input to hash function
        let mut note_b = Vec::new();
        note_b.extend(b_bits.clone());
        note_b.extend(symbol_bits.clone());
        note_b.extend(rho_b_bits.clone());
        note_b.extend(h_sk_b_bits.clone());
        // boolean bit vector Z_b := h(b | h_sk_b | rho_b)
        let z_b_bits = blake2s::blake2s(cs.namespace(|| "blake2s(b | h_sk_b | rho_b)"), &note_b, &[0; 8])?;

        // calculate the note commitment Z_c of value 'c' which is defined as: Z_c := h(c | h_sk_a | rho_c)
        // 'c' to boolean bit vector
        let c_bits = boolean::u64_into_boolean_vec_le(
            cs.namespace(|| "c"),
            self.c
        )?;
        // rho_c to boolean bit vector
        let rho_c_bits = boolean::u8_vec_into_boolean_vec_le(
            cs.namespace(|| "rho_c"),
            self.rho_c,
        )?;
        // concatenate (c | h_sk_a | rho_c) for input to hash function
        let mut note_c = Vec::new();
        note_c.extend(c_bits.clone());
        note_c.extend(symbol_bits.clone());
        note_c.extend(rho_c_bits.clone());
        note_c.extend(h_sk_a_bits.clone());
        // boolean bit vector Z_c := h(c | h_sk_a | rho_c)
        let z_c_bits = blake2s::blake2s(cs.namespace(|| "blake2s(c | h_sk_a | rho_c)"), &note_c, &[0; 8])?;

        // calculate the nullifier N_a of value 'a' which is defined as: N_a := h(rho_a | sk_a)
        // concatenate (rho_a | sk_a) for input to hash function
        let mut nf_a = Vec::new();
        nf_a.extend(rho_a_bits.clone());
        nf_a.extend(sk_a_bits.clone());
        // boolean bit vector N_a := h(rho_a | sk_a)
        let nf_a_bits = blake2s::blake2s(cs.namespace(|| "blake2s(rho_a | sk_a)"), &nf_a, &[0; 8])?;

        // calculate merkle tree root rt_M using the authenticator path
        // Witness into the merkle tree
        let mut cur = z_a_bits;
        for (i, layer) in self.auth_path.iter().enumerate() {
            let cs = &mut cs.namespace(|| format!("layer {}", i));

            // Determines if the current subtree is the "right" leaf at this
            // depth of the tree.
            let cur_is_right = boolean::AllocatedBit::alloc(
                cs.namespace(|| "cur is right"),
                layer.map(|(_, p)| p),
            )?;

            // set current subtree to left hand side and the sibling to the right hand side
            let lhs = cur;
            let rhs = boolean::u8_vec_into_boolean_vec_le(
                cs.namespace(|| "sibling"),
                layer.map(|(sibling, _)| sibling),
            )?;

            // Conditionally swap left and right hand side if the current subtree is on the right
            // and concatenate (lhs | rhs) as preimage for input to hash function
            let preimage = conditionally_swap_u256(
                cs.namespace(|| "conditional swap"),
                &lhs[..],
                &rhs[..],
                &cur_is_right,
            )?;

            // calculate hash of parent node and set as new current subtree
            cur = blake2s::blake2s(cs.namespace(|| "blake2s(lhs | rhs)"), &preimage, &[0; 8])?;
        }

        // enforce a = b + c
        let val_a = NoteValue::new(cs.namespace(|| "val_a"), self.a)?;
        let val_b = NoteValue::new(cs.namespace(|| "val_b"), self.b)?;
        let val_c = NoteValue::new(cs.namespace(|| "val_c"), self.c)?;
        let lhs = val_b.lc() + &val_c.lc();
        let rhs = val_a.lc();
        cs.enforce(
            || "balance equation: (b + c) * 1 = a",
            |_| lhs,
            |lc| lc + CS::one(),
            |_| rhs,
        );

        // expose public inputs: N_a, Z_b, Z_c, cur
        let mut inputs = vec![];
        inputs.extend(nf_a_bits);
        inputs.extend(z_b_bits);
        inputs.extend(z_c_bits);
        inputs.extend(cur);

        return multipack::pack_into_inputs(cs.namespace(|| "pack inputs"), &inputs);
    }
}

/// This is an instance of the `Burn` circuit.
pub struct Burn
{
    // secret key to spend a
    pub sk_a: Option<[u8; 32]>,

    // value of note which is being burned
    pub a: Option<u64>,

    // value which is received by EOS account
    pub b: Option<u64>,

    // the "change" that goes back to pk(sk)
    // a = b + c
    pub c: Option<u64>,

    // the symbol of the notes (only one because it must be the same for both notes)
    pub symbol: Option<u64>,

    // salts for note commitments
    pub rho_a: Option<[u8; 32]>,
    pub rho_c: Option<[u8; 32]>,

    // authentication path in the merkle tree i.e. the sister path of note commitment of value 'a'
    pub auth_path: [Option<([u8; 32], bool)>; TREE_DEPTH]
}

impl Circuit<bls12_381::Scalar> for Burn
{
    fn synthesize<CS: ConstraintSystem<bls12_381::Scalar>>(
        self,
        cs: &mut CS,
    ) -> Result<(), SynthesisError>
    {
        // calculate h_sk_a of sk_a which is defined as: h_sk_a := h(sk_a)
        // sk_a to boolean bit vector
        let sk_a_bits = boolean::u8_vec_into_boolean_vec_le(
            cs.namespace(|| "sk_a"),
            self.sk_a,
        )?;
        // boolean bit vector h_sk_a := h(sk_a)
        let h_sk_a_bits = blake2s::blake2s(cs.namespace(|| "blake2s(sk_a)"), &sk_a_bits, &[0; 8])?;

        // symbol to boolean bit vector
        let symbol_bits = boolean::u64_into_boolean_vec_le(
            cs.namespace(|| "symbol"),
            self.symbol
        )?;

        // calculate the note commitment Z_a of value 'a' which is defined as: Z_a := h(a | h_sk_a | rho_a)
        // 'a' to boolean bit vector
        let a_bits = boolean::u64_into_boolean_vec_le(
            cs.namespace(|| "a"),
            self.a
        )?;
        // rho_a to boolean bit vector
        let rho_a_bits = boolean::u8_vec_into_boolean_vec_le(
            cs.namespace(|| "rho_a"),
            self.rho_a,
        )?;
        // concatenate (a | h_sk_a | rho_a) for input to hash function
        let mut note_a = Vec::new();
        note_a.extend(a_bits.clone());
        note_a.extend(symbol_bits.clone());
        note_a.extend(rho_a_bits.clone());
        note_a.extend(h_sk_a_bits.clone());
        // boolean bit vector Z_a := h(a | h_sk_a | rho_a)
        let z_a_bits = blake2s::blake2s(cs.namespace(|| "blake2s(a | h_sk_a | rho_a)"), &note_a, &[0; 8])?;

        // calculate the bit vector of value 'b' to expose it as public input
        // 'b' to boolean bit vector
        let b_bits = boolean::u64_into_boolean_vec_le(
            cs.namespace(|| "b"),
            self.b
        )?;

        // calculate the note commitment Z_c of value 'c' which is defined as: Z_c := h(c | h_sk_a | rho_c)
        // 'c' to boolean bit vector
        let c_bits = boolean::u64_into_boolean_vec_le(
            cs.namespace(|| "c"),
            self.c
        )?;
        // rho_c to boolean bit vector
        let rho_c_bits = boolean::u8_vec_into_boolean_vec_le(
            cs.namespace(|| "rho_c"),
            self.rho_c,
        )?;
        // concatenate (c | h_sk_a | rho_c) for input to hash function
        let mut note_c = Vec::new();
        note_c.extend(c_bits.clone());
        note_c.extend(symbol_bits.clone());
        note_c.extend(rho_c_bits.clone());
        note_c.extend(h_sk_a_bits.clone());
        // boolean bit vector Z_b := h(b | pk_b | rho_b)
        let z_c_bits = blake2s::blake2s(cs.namespace(|| "blake2s(c | h_sk_a | rho_c)"), &note_c, &[0; 8])?;

        // calculate the nullifier N_a of value 'a' which is defined as: N_a := h(rho_a | sk_a)
        // concatenate (rho_a | sk_a) for input to hash function
        let mut nf_a = Vec::new();
        nf_a.extend(rho_a_bits.clone());
        nf_a.extend(sk_a_bits.clone());
        // boolean bit vector nf_a := h(rho_a | sk_a)
        let nf_a_bits = blake2s::blake2s(cs.namespace(|| "blake2s(rho_a | sk_a)"), &nf_a, &[0; 8])?;

        // calculate merkle tree root rt_M using the authenticator path
        // Witness into the merkle tree
        let mut cur = z_a_bits;
        for (i, layer) in self.auth_path.iter().enumerate() {
            let cs = &mut cs.namespace(|| format!("layer {}", i));

            // Determines if the current subtree is the "right" leaf at this
            // depth of the tree.
            let cur_is_right = boolean::AllocatedBit::alloc(
                cs.namespace(|| "cur is right"),
                layer.map(|(_, p)| p),
            )?;

            // set current subtree to left hand side and the sibling to the right hand side
            let lhs = cur;
            let rhs = boolean::u8_vec_into_boolean_vec_le(
                cs.namespace(|| "sibling"),
                layer.map(|(sibling, _)| sibling),
            )?;

            // Conditionally swap left and right hand side if the current subtree is on the right
            // and concatenate (lhs | rhs) as preimage for input to hash function
            let preimage = conditionally_swap_u256(
                cs.namespace(|| "conditional swap"),
                &lhs[..],
                &rhs[..],
                &cur_is_right,
            )?;

            // calculate hash of parent node and set as new current subtree
            cur = blake2s::blake2s(cs.namespace(|| "blake2s(lhs | rhs)"), &preimage, &[0; 8])?;
        }

        // enforce a = b + c
        let val_a = NoteValue::new(cs.namespace(|| "val_a"), self.a)?;
        let val_b = NoteValue::new(cs.namespace(|| "val_b"), self.b)?;
        let val_c = NoteValue::new(cs.namespace(|| "val_c"), self.c)?;
        let lhs = val_b.lc() + &val_c.lc();
        let rhs = val_a.lc();
        cs.enforce(
            || "balance equation: (b + c) * 1 = a",
            |_| lhs,
            |lc| lc + CS::one(),
            |_| rhs,
        );

        // expose public inputs: nf_a, b, z_c, cur
        let mut inputs = vec![];
        inputs.extend(nf_a_bits);
        inputs.extend(b_bits);
        inputs.extend(symbol_bits);
        inputs.extend(z_c_bits);
        inputs.extend(cur);

        return multipack::pack_into_inputs(cs.namespace(|| "pack inputs"), &inputs);
    }
}

pub struct NoteValue {
    value: Option<u64>,
    // Least significant digit firstCatemaco, 
    bits: Vec<boolean::AllocatedBit>,
}

impl NoteValue {
    fn new<Scalar, CS>(mut cs: CS, value: Option<u64>) -> Result<NoteValue, SynthesisError>
    where
        Scalar: PrimeField,
        CS: ConstraintSystem<Scalar>,
    {
        let mut values;
        match value {
            Some(mut val) => {
                values = vec![];
                for _ in 0..64 {
                    values.push(Some(val & 1 == 1));
                    val >>= 1;
                }
            }
            None => {
                values = vec![None; 64];
            }
        }

        let mut bits = vec![];
        for (i, value) in values.into_iter().enumerate() {
            bits.push(boolean::AllocatedBit::alloc(
                cs.namespace(|| format!("bit {}", i)),
                value,
            )?);
        }

        Ok(NoteValue { value, bits })
    }

    /// Computes this value as a linear combination of
    /// its bits.
    fn lc<Scalar: PrimeField>(&self) -> LinearCombination<Scalar> {
        let mut tmp = LinearCombination::zero();

        let mut coeff = Scalar::one();
        for b in &self.bits {
            tmp = tmp + (coeff, b.get_variable());
            coeff = coeff.double();
        }

        tmp
    }
}

/// Swaps two 256-bit blobs conditionally, returning the
/// 512-bit concatenation.
pub fn conditionally_swap_u256<Scalar, CS>(
    mut cs: CS,
    lhs: &[boolean::Boolean],
    rhs: &[boolean::Boolean],
    condition: &boolean::AllocatedBit,
) -> Result<Vec<boolean::Boolean>, SynthesisError>
where
    Scalar: PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    assert_eq!(lhs.len(), 256);
    assert_eq!(rhs.len(), 256);

    let mut new_lhs = vec![];
    let mut new_rhs = vec![];

    for (i, (lhs, rhs)) in lhs.iter().zip(rhs.iter()).enumerate() {
        let cs = &mut cs.namespace(|| format!("bit {}", i));

        let x = boolean::Boolean::from(boolean::AllocatedBit::alloc(
            cs.namespace(|| "x"),
            condition
                .get_value()
                .and_then(|v| if v { rhs.get_value() } else { lhs.get_value() }),
        )?);

        // x = (1-condition)lhs + (condition)rhs
        // x = lhs - lhs(condition) + rhs(condition)
        // x - lhs = condition (rhs - lhs)
        // if condition is zero, we don't swap, so
        //   x - lhs = 0
        //   x = lhs
        // if condition is one, we do swap, so
        //   x - lhs = rhs - lhs
        //   x = rhs
        cs.enforce(
            || "conditional swap for x",
            |lc| lc + &rhs.lc(CS::one(), Scalar::one()) - &lhs.lc(CS::one(), Scalar::one()),
            |lc| lc + condition.get_variable(),
            |lc| lc + &x.lc(CS::one(), Scalar::one()) - &lhs.lc(CS::one(), Scalar::one()),
        );

        let y = boolean::Boolean::from(boolean::AllocatedBit::alloc(
            cs.namespace(|| "y"),
            condition
                .get_value()
                .and_then(|v| if v { lhs.get_value() } else { rhs.get_value() }),
        )?);

        // y = (1-condition)rhs + (condition)lhs
        // y - rhs = condition (lhs - rhs)
        cs.enforce(
            || "conditional swap for y",
            |lc| lc + &lhs.lc(CS::one(), Scalar::one()) - &rhs.lc(CS::one(), Scalar::one()),
            |lc| lc + condition.get_variable(),
            |lc| lc + &y.lc(CS::one(), Scalar::one()) - &rhs.lc(CS::one(), Scalar::one()),
        );

        new_lhs.push(x);
        new_rhs.push(y);
    }

    let mut f = new_lhs;
    f.extend(new_rhs);

    assert_eq!(f.len(), 512);

    Ok(f)
}

#[cfg(test)]
mod tests
{
    use rand::rngs::OsRng;
    use blake2s_simd::{Hash, Params as blake2s_simd_params};
    use bellman::gadgets::multipack;
    use bellman::groth16;
    use super::{Mint, Transfer, Burn, TREE_DEPTH};
    use crate::Bls12;

    #[test]
    fn test_mint()
    {
        println!("Create parameters for our circuit. In a production deployment these would be generated securely using a multiparty computation.");
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

        println!("Prepare the verification key (for proof verification).");
        let pvk = groth16::prepare_verifying_key(&params.vk);

        println!("Pick test values for Mint circuit.");
        //let quantity = Asset::new(100000, Symbol::new(4, "ZEOS".to_string()));
        let amount: u64 = 100000;//quantity.amount().try_into().unwrap();
        let symbol: u64 = 357812230660;//quantity.symbol().value();
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

        println!("Create a Groth16 proof with our parameters.");
        let proof = groth16::create_random_proof(c, &params, &mut OsRng).unwrap();

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
    }

    #[test]
    fn test_ztransfer()
    {
        println!("Create parameters for our circuit. In a production deployment these would be generated securely using a multiparty computation.");
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

        println!("Prepare the verification key (for proof verification).");
        let pvk = groth16::prepare_verifying_key(&params.vk);

        println!("Pick test values for Transfer circuit.");
        //let q_a = Asset::new(100000, Symbol::new(4, "ZEOS".to_string()));
        //let q_b = Asset::new(100000, Symbol::new(4, "ZEOS".to_string()));
        //let q_c = Asset::new(0, Symbol::new(4, "ZEOS".to_string()));
        let sk_a: [u8; 32] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32];
        let mut image = Vec::new();
        image.extend(sk_a.clone());
        let h_sk_a = blake2s_simd_params::new()
            .personal(&[0; 8])
            .to_state()
            .update(&image)
            .finalize();
        let a: u64 = 100000;
        let b: u64 = 100000;
        let c: u64 = 0;
        let symbol: u64 = 357812230660;
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
        
        println!("Create a Groth16 proof with our parameters.");
        let proof = groth16::create_random_proof(c, &params, &mut OsRng).unwrap();
        
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

        println!("Check the proof!");
        assert!(groth16::verify_proof(&pvk, &proof, &inputs).is_ok());
    }

    #[test]
    fn test_burn()
    {
        println!("Create parameters for our circuit. In a production deployment these would be generated securely using a multiparty computation.");
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

        println!("Prepare the verification key (for proof verification).");
        let pvk = groth16::prepare_verifying_key(&params.vk);

        println!("Pick test values for Burn circuit.");
        //let q_a = Asset::new(100000, Symbol::new(4, "ZEOS".to_string()));
        //let q_b = Asset::new(100000, Symbol::new(4, "ZEOS".to_string()));
        //let q_c = Asset::new(0, Symbol::new(4, "ZEOS".to_string()));
        let sk_a: [u8; 32] = [42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42];//[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32];
        let mut image = Vec::new();
        image.extend(sk_a.clone());
        let h_sk_a = blake2s_simd_params::new()
            .personal(&[0; 8])
            .to_state()
            .update(&image)
            .finalize();
        let a: u64 = 100000;
        let b: u64 = 100000;
        let c: u64 = 0;
        let symbol: u64 = 357812230660;
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

        println!("Check the proof!");
        assert!(groth16::verify_proof(&pvk, &proof, &inputs).is_ok());
    }
}