#![doc = include_str!("../README.md")]

use ark_bls12_381::{Bls12_381 as F, G1Projective, G2Projective};
use ark_ec::{pairing::Pairing, Group};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{One, UniformRand, Zero};
use rand_core::RngCore;
use std::ops::Mul;

pub type G1 = G1Projective;
pub type G2 = G2Projective;
pub type Fr = <F as Pairing>::ScalarField;

#[derive(Clone, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct PublicParams {
    // generators
    pub p1: G1,
    pub p2: G2,
}

impl PublicParams {
    pub fn new<R: RngCore>(rng: &mut R) -> Self {
        let p1 = G1::rand(rng);
        let p2 = G2::rand(rng);
        PublicParams { p1, p2 }
    }

    pub fn key_gen<R: RngCore>(&self, rng: &mut R, size: u32) -> (PublicKey, SecretKey) {
        let x = (0..size).map(|_| Fr::rand(rng)).collect::<Vec<Fr>>();
        let bx = x.iter().map(|xi| self.p2.mul(xi)).collect();
        (PublicKey { bx }, SecretKey { x })
    }
}

impl Default for PublicParams {
    fn default() -> Self {
        PublicParams {
            p1: G1::generator(),
            p2: G2::generator(),
        }
    }
}

#[derive(Clone, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct SecretKey {
    // sk = (x1,...,xl)
    x: Vec<Fr>,
}

impl SecretKey {
    /// Sign a message.
    ///
    /// ## Example
    ///
    /// ```rust
    /// use mercurial_signature::{PublicParams, G1};
    /// use ark_std::UniformRand;
    /// use rand::thread_rng;
    ///
    /// let mut rng = rand::thread_rng();
    /// let pp = PublicParams::new(&mut rng);
    /// let (pk, sk) = pp.key_gen(&mut rng, 10);
    /// let message = (0..10).map(|_| G1::rand(&mut rng)).collect::<Vec<G1>>();
    /// let sig = sk.sign(&mut rng, &pp, &message);
    /// assert!(pk.verify(&pp, &message, &sig));
    /// ```
    pub fn sign<R: RngCore>(&self, rng: &mut R, pp: &PublicParams, message: &[G1]) -> Signature {
        let y = Fr::rand(rng);
        // z = (x1 M1 + ... + xl Ml) * y
        let z = message
            .iter()
            .zip(self.x.iter())
            .fold(G1::zero(), |acc, (m, xi)| acc + m.mul(y * xi));
        // y1 = p1^(1/y)
        let y1 = pp.p1.mul(Fr::one() / y);
        // y2 = p2^(1/y)
        let y2 = pp.p2.mul(Fr::one() / y);
        Signature { z, y1, y2 }
    }

    /// Convert the secret key.
    /// This function converts the secret key to a new secret key that is equivalent to the original secret key.
    /// The input scalar `p` must be the same as the one used in the conversion of the public key and the signature.
    ///
    /// ## Example
    ///
    /// ```rust
    /// use mercurial_signature::{PublicParams, G1, Fr};
    /// use ark_std::UniformRand;
    /// use rand::thread_rng;
    ///
    /// let mut rng = rand::thread_rng();
    /// let pp = PublicParams::new(&mut rng);
    /// let (mut pk, mut sk) = pp.key_gen(&mut rng, 10);
    /// let message = (0..10).map(|_| G1::rand(&mut rng)).collect::<Vec<G1>>();
    /// let mut sig = sk.sign(&mut rng, &pp, &message);
    ///
    /// let p = Fr::rand(&mut rng);
    /// pk.convert(p);
    /// sk.convert(p);
    /// sig.convert(&mut rng, p);
    /// assert!(pk.verify(&pp, &message, &sig));
    /// ```
    pub fn convert(&mut self, p: Fr) {
        self.x.iter_mut().for_each(|xi| *xi *= p);
    }
}

#[derive(Clone, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct PublicKey {
    // pk = (p2^x1,...,p2^xl) where (x1,...,xl) is the secret key
    bx: Vec<G2>,
}

impl PublicKey {
    /// Verify a signature.
    ///
    /// ## Example
    ///
    /// ```rust
    /// use mercurial_signature::{PublicParams, G1};
    /// use ark_std::UniformRand;
    /// use rand::thread_rng;
    ///
    /// let mut rng = rand::thread_rng();
    /// let pp = PublicParams::new(&mut rng);
    /// let (pk, sk) = pp.key_gen(&mut rng, 10);
    /// let message = (0..10).map(|_| G1::rand(&mut rng)).collect::<Vec<G1>>();
    /// let sig = sk.sign(&mut rng, &pp, &message);
    /// assert!(pk.verify(&pp, &message, &sig));
    /// ```
    pub fn verify(&self, pp: &PublicParams, message: &[G1], sig: &Signature) -> bool {
        // check length l
        if message.len() != self.bx.len() {
            return false;
        }

        // e(y1, p2) == e(p1, y2)
        let lhs = F::pairing(sig.y1, pp.p2);
        let rhs = F::pairing(pp.p1, sig.y2);
        if lhs != rhs {
            return false;
        }

        // e(z, y2) == e(m1, bx1) * ... * e(ml, bxl)
        let lhs = F::pairing(sig.z, sig.y2);
        let rhs = message
            .iter()
            .zip(self.bx.iter())
            .fold(F::pairing(G1::zero(), G2::zero()), |acc, (m, bxi)| {
                acc + F::pairing(*m, *bxi)
            });
        lhs == rhs
    }

    /// Convert the public key.
    /// This function converts the public key to a new public key that is equivalent to the original public key.
    /// The input scalar `p` must be the same as the one used in the conversion of the secret key and the signature.
    ///
    /// ## Example
    ///
    /// ```rust
    /// use mercurial_signature::{PublicParams, G1, Fr};
    /// use ark_std::UniformRand;
    /// use rand::thread_rng;
    ///
    /// let mut rng = rand::thread_rng();
    /// let pp = PublicParams::new(&mut rng);
    /// let (mut pk, mut sk) = pp.key_gen(&mut rng, 10);
    /// let message = (0..10).map(|_| G1::rand(&mut rng)).collect::<Vec<G1>>();
    /// let mut sig = sk.sign(&mut rng, &pp, &message);
    ///
    /// let p = Fr::rand(&mut rng);
    /// pk.convert(p);
    /// sk.convert(p);
    /// sig.convert(&mut rng, p);
    /// assert!(pk.verify(&pp, &message, &sig));
    /// ```
    pub fn convert(&mut self, p: Fr) {
        self.bx.iter_mut().for_each(|bxi| *bxi *= p);
    }
}

#[derive(Clone, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Signature {
    z: G1,
    y1: G1,
    y2: G2,
}

impl Signature {
    /// Convert the signature.
    /// This function converts the signature to a new signature that is equivalent to the original signature.
    /// The input scalar `p` must be the same as the one used in the conversion of the public key and the secret key.
    ///
    /// ## Example
    ///
    /// ```rust
    /// use mercurial_signature::{PublicParams, G1, Fr};
    /// use ark_std::UniformRand;
    /// use rand::thread_rng;
    ///
    /// let mut rng = rand::thread_rng();
    /// let pp = PublicParams::new(&mut rng);
    /// let (mut pk, mut sk) = pp.key_gen(&mut rng, 10);
    /// let message = (0..10).map(|_| G1::rand(&mut rng)).collect::<Vec<G1>>();
    /// let mut sig = sk.sign(&mut rng, &pp, &message);
    ///
    /// let p = Fr::rand(&mut rng);
    /// pk.convert(p);
    /// sk.convert(p);
    /// sig.convert(&mut rng, p);
    /// assert!(pk.verify(&pp, &message, &sig));
    /// ```
    pub fn convert<R: RngCore>(&mut self, rng: &mut R, p: Fr) {
        let f = Fr::rand(rng);
        self.convert_with_f(p, f);
    }

    /// Convert the signature with a scalar `f`.
    fn convert_with_f(&mut self, p: Fr, f: Fr) {
        self.z *= p * f;
        self.y1 *= Fr::one() / f;
        self.y2 *= Fr::one() / f;
    }
}

/// Change the representation of the message and the signature.
///
/// ## Example
///
///
/// ```rust
/// use mercurial_signature::{PublicParams, G1, Fr, change_representation};
/// use ark_std::UniformRand;
/// use rand::thread_rng;
///
/// let mut rng = rand::thread_rng();
/// let pp = PublicParams::new(&mut rng);
/// let (pk, sk) = pp.key_gen(&mut rng, 10);
/// let mut message = (0..10).map(|_| G1::rand(&mut rng)).collect::<Vec<G1>>();
/// let mut sig = sk.sign(&mut rng, &pp, &message);
///
/// let u = Fr::rand(&mut rng);
/// change_representation(&mut rng, &mut message, &mut sig, u);
/// assert!(pk.verify(&pp, &message, &sig));
/// ```
pub fn change_representation<R: RngCore>(
    rng: &mut R,
    message: &mut [G1],
    signature: &mut Signature,
    u: Fr,
) {
    let f = Fr::rand(rng);
    signature.convert_with_f(u, f);

    message.iter_mut().for_each(|mi| *mi *= u);
}
