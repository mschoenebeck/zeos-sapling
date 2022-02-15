
use ff::PrimeField;
use group::Curve;

use bellman::{Circuit, ConstraintSystem, LinearCombination, SynthesisError};

use bellman::gadgets::blake2s;
use bellman::gadgets::boolean;
use bellman::gadgets::multipack;
use bellman::gadgets::num;
use bellman::gadgets::Assignment;

#[cfg(test)]
use ff::PrimeFieldBits;

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
