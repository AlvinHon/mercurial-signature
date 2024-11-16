use std::ops::Mul;

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::UniformRand;
use rand_core::RngCore;

use crate::{public_key::PublicKey, secret_key::SecretKey, Curve};

#[derive(Clone, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct PublicParams<C>
where
    C: Curve,
{
    // generators
    pub p1: C::G1,
    pub p2: C::G2,
}

impl<C> PublicParams<C>
where
    C: Curve,
{
    /// Generate public parameters.
    pub fn new<R: RngCore>(rng: &mut R) -> Self {
        let p1 = C::G1::rand(rng);
        let p2 = C::G2::rand(rng);
        PublicParams { p1, p2 }
    }

    /// Generate a key pair.
    pub fn key_gen<R: RngCore>(&self, rng: &mut R, size: u32) -> (PublicKey<C>, SecretKey<C>) {
        let x = (0..size).map(|_| C::Fr::rand(rng)).collect::<Vec<C::Fr>>();
        let bx: Vec<C::G2> = x.iter().map(|xi| self.p2.mul(xi)).collect();
        (PublicKey { bx }, SecretKey { x })
    }
}
