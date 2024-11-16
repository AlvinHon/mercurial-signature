use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{One, UniformRand};
use rand_core::RngCore;

use crate::Curve;

#[derive(Clone, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Signature<C>
where
    C: Curve,
{
    pub(crate) z: C::G1,
    pub(crate) y1: C::G1,
    pub(crate) y2: C::G2,
}

impl<C> Signature<C>
where
    C: Curve,
{
    /// Convert the signature.
    /// This function converts the signature to a new signature that is equivalent to the original signature.
    /// The input scalar `p` must be the same as the one used in the conversion of the public key and the secret key.
    ///
    /// ## Example
    ///
    /// ```rust
    /// use mercurial_signature::{Curve, CurveBls12_381, PublicParams};
    /// use ark_std::UniformRand;
    /// use rand::thread_rng;
    ///
    /// type G1 = <CurveBls12_381 as Curve>::G1;
    /// type Fr = <CurveBls12_381 as Curve>::Fr;
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
    pub fn convert<R: RngCore>(&mut self, rng: &mut R, p: C::Fr) {
        let f = C::Fr::rand(rng);
        self.convert_with_f(p, f);
    }

    /// Convert the signature with a scalar `f`.
    pub(crate) fn convert_with_f(&mut self, p: C::Fr, f: C::Fr) {
        self.z *= p * f;
        self.y1 *= C::Fr::one() / f;
        self.y2 *= C::Fr::one() / f;
    }
}
