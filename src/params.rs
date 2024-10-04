use std::ops::Mul;

use ark_ff::UniformRand;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rand_core::RngCore;

use crate::{extension, public_key::PublicKey, secret_key::SecretKey, Curve};

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

    /// Generate a key pair for a mercurial signature extension (i.e. mercurial signature with variable-length messages).
    pub fn key_gen_ex<R: RngCore>(
        &self,
        rng: &mut R,
    ) -> (extension::PublicKey<C>, extension::SecretKey<C>) {
        let (pk, sk) = self.key_gen(rng, 5);

        let x = C::Fr::rand(rng);
        let y1 = C::Fr::rand(rng);
        let y2 = C::Fr::rand(rng);

        let x6 = C::Fr::rand(rng);
        let x7 = x6 * x;
        let x8 = C::Fr::rand(rng);
        let x9 = x8 * y1;
        let x10 = x8 * y2;
        (
            extension::PublicKey {
                pk,
                _bx6: self.p2.mul(&x6),
                _bx7: self.p2.mul(&x7),
                _bx8: self.p2.mul(&x8),
                _bx9: self.p2.mul(&x9),
                _bx10: self.p2.mul(&x10),
            },
            extension::SecretKey {
                sk,
                x6,
                x7,
                x8,
                x9,
                x10,
            },
        )
    }
}
