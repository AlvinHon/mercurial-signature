#![doc = include_str!("../README.md")]

use ark_ec::pairing::Pairing;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{One, UniformRand, Zero};
use std::ops::{Add, Div, Mul, MulAssign};

mod params;
mod public_key;

mod representation;
pub use representation::change_representation;

mod secret_key;
mod signature;

pub trait Curve: Clone {
    type F: Pairing;
    type Fr: Clone
        + Copy
        + PartialEq
        + Eq
        + CanonicalSerialize
        + CanonicalDeserialize
        + UniformRand
        + One
        + Mul
        + MulAssign
        + for<'a> Mul<&'a Self::Fr, Output = Self::Fr>
        + Div<Output = Self::Fr>;
    type G1: Clone
        + Copy
        + PartialEq
        + Eq
        + CanonicalSerialize
        + CanonicalDeserialize
        + UniformRand
        + Zero
        + Into<<<Self as Curve>::F as Pairing>::G1Prepared>
        + Add
        + for<'a> Mul<&'a Self::Fr, Output = Self::G1>
        + Mul<Self::Fr, Output = Self::G1>
        + MulAssign<Self::Fr>;
    type G2: Clone
        + Copy
        + PartialEq
        + Eq
        + CanonicalSerialize
        + CanonicalDeserialize
        + UniformRand
        + Zero
        + Into<<<Self as Curve>::F as Pairing>::G2Prepared>
        + for<'a> Mul<&'a Self::Fr, Output = Self::G2>
        + Mul<Self::Fr, Output = Self::G2>
        + MulAssign<Self::Fr>;
}

#[derive(Clone, PartialEq, Eq)]
pub struct CurveBls12_381;

impl Curve for CurveBls12_381 {
    type F = ark_bls12_381::Bls12_381;
    type Fr = <ark_bls12_381::Bls12_381 as Pairing>::ScalarField;
    type G1 = ark_bls12_381::G1Projective;
    type G2 = ark_bls12_381::G2Projective;
}

pub type PublicParams = params::PublicParams<CurveBls12_381>;
pub type PublicKey = public_key::PublicKey<CurveBls12_381>;
pub type SecretKey = secret_key::SecretKey<CurveBls12_381>;
pub type Signature = signature::Signature<CurveBls12_381>;
