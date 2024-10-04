use ark_ec::pairing::Pairing;
use ark_ff::Zero;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use crate::{params::PublicParams, signature::Signature, Curve};

#[derive(Clone, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct PublicKey<C>
where
    C: Curve,
{
    // pk = (p2^x1,...,p2^xl) where (x1,...,xl) is the secret key
    pub(crate) bx: Vec<C::G2>,
}

impl<C> PublicKey<C>
where
    C: Curve,
{
    /// Length of the public key.
    pub fn length(&self) -> usize {
        self.bx.len()
    }

    /// Convert the public key.
    /// This function converts the public key to a new public key that is equivalent to the original public key.
    /// The input scalar `p` must be the same as the one used in the conversion of the secret key and the signature.
    ///
    /// ## Example
    ///
    /// ```rust
    /// use mercurial_signature::{Curve, CurveBls12_381, PublicParams, change_representation};
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
    pub fn verify(&self, pp: &PublicParams<C>, message: &[C::G1], sig: &Signature<C>) -> bool {
        // check length l
        if self.bx.len() < message.len() {
            return false;
        }

        // e(y1, p2) == e(p1, y2)
        let lhs = C::F::pairing(sig.y1, pp.p2);
        let rhs = C::F::pairing(pp.p1, sig.y2);
        if lhs != rhs {
            return false;
        }

        // e(z, y2) == e(m1, bx1) * ... * e(ml, bxl)
        let lhs = C::F::pairing(sig.z, sig.y2);
        let rhs = message.iter().zip(self.bx.iter()).fold(
            C::F::pairing(C::G1::zero(), C::G2::zero()),
            |acc, (m, bxi)| acc + C::F::pairing(*m, *bxi),
        );
        lhs == rhs
    }

    /// Convert the public key.
    /// This function converts the public key to a new public key that is equivalent to the original public key.
    /// The input scalar `p` must be the same as the one used in the conversion of the secret key and the signature.
    ///
    /// ## Example
    ///
    /// ```rust
    /// use mercurial_signature::{Curve, CurveBls12_381, PublicParams, change_representation};
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
    pub fn convert(&mut self, p: C::Fr) {
        self.bx.iter_mut().for_each(|bxi| *bxi *= p);
    }
}
