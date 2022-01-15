//! *Zcash circuits and proofs.*
//!
//! `zcash_proofs` contains the zk-SNARK circuits used by Zcash, and the APIs for creating
//! and verifying proofs.

#![cfg_attr(docsrs, feature(doc_cfg))]
// Catch documentation errors caused by code changes.
#![deny(broken_intra_doc_links)]
// Temporary until we have addressed all Result<T, ()> cases.
#![allow(clippy::result_unit_err)]

use bellman::groth16::{prepare_verifying_key, Parameters, PreparedVerifyingKey, VerifyingKey};
use bls12_381::Bls12;


pub mod circuit;
//pub mod constants;



