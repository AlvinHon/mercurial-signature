use crate::{params::PublicParams, Curve};
use ark_ff::{One, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rand_core::RngCore;
use std::ops::Mul;

use super::{representation::VarMessage, signature::VarSignature};

#[derive(Clone, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct SecretKey<C>
where
    C: Curve,
{
    // secret key with length = 5. i.e. (x1, x2, x3, x4, x5)
    pub(crate) sk: crate::secret_key::SecretKey<C>,
    // random
    pub(crate) x6: C::Fr,
    // x7 = x6 * x
    pub(crate) x7: C::Fr,
    // random
    pub(crate) x8: C::Fr,
    // x9 = x8 * y1
    pub(crate) x9: C::Fr,
    // x10 = x8 * y2
    pub(crate) x10: C::Fr,
}

impl<C> SecretKey<C>
where
    C: Curve,
{
    /// Sign a signature on a variable-length message.
    ///
    /// ## Example
    ///
    /// ```rust
    /// use ark_std::UniformRand;
    /// use mercurial_signature::{
    ///     extension::representation::VarMessage, Curve, CurveBls12_381, PublicParams,
    /// };
    ///
    /// type G1 = <CurveBls12_381 as Curve>::G1;
    /// type Fr = <CurveBls12_381 as Curve>::Fr;
    ///
    /// let rng = &mut rand::thread_rng();
    /// let pp = PublicParams::new(rng);
    /// let (pk, sk) = pp.key_gen_ex(rng);
    ///
    /// let var_message = {
    ///     let message = (0..10).map(|_| Fr::rand(rng)).collect::<Vec<Fr>>();
    ///     let g = G1::rand(rng);
    ///     VarMessage::new(g, &message)
    /// };
    /// let sig = sk.sign(rng, &pp, &var_message);
    /// assert!(pk.verify(&pp, &var_message, &sig));
    /// ```
    pub fn sign<R: RngCore>(
        &self,
        rng: &mut R,
        pp: &PublicParams<C>,
        message: &VarMessage<C>,
    ) -> VarSignature<C> {
        // x = x7 * x6^-1
        let x = self.x7 * (C::Fr::one() / self.x6);
        // y1 = x9 * x8^-1
        let y1 = self.x9 * (C::Fr::one() / self.x8);
        // y2 = x10 * x8^-1
        let y2 = self.x10 * (C::Fr::one() / self.x8);
        // y = y1 * y2
        let y = y1 * y2;
        // h = (u1 * u2^x ... * un^x^n-1) ^ y
        let h = {
            let mut h = C::G1::zero();
            let mut xi = C::Fr::one();
            for i in 0..message.u.len() {
                if i > 0 {
                    xi *= x;
                }
                h = h + message.u[i].mul(xi * y);
            }
            h
        };
        // Mi = (g, g^i, g^n, h, ui)
        let ms = message.to_tuples(h);
        // sign on ms
        let sigs = ms.into_iter().map(|m| self.sk.sign(rng, pp, &m)).collect();
        VarSignature { h, sigs }
    }

    /// Convert the secret key.
    /// This function converts the secret key to a new secret key that is equivalent to the original secret key.
    /// The input scalar `p` must be the same as the one used in the conversion of the public key and the signature.
    ///
    /// ## Example
    ///
    /// ```rust
    /// use ark_std::UniformRand;
    /// use mercurial_signature::{
    ///     extension::representation::VarMessage, Curve, CurveBls12_381, PublicParams,
    /// };
    ///
    /// type G1 = <CurveBls12_381 as Curve>::G1;
    /// type Fr = <CurveBls12_381 as Curve>::Fr;
    ///
    /// let rng = &mut rand::thread_rng();
    /// let pp = PublicParams::new(rng);
    /// let (mut pk, mut sk) = pp.key_gen_ex(rng);
    ///
    /// let p = Fr::rand(rng);
    /// pk.convert(p);
    /// sk.convert(p);
    ///
    /// let var_message = {
    ///     let message = (0..10).map(|_| Fr::rand(rng)).collect::<Vec<Fr>>();
    ///     let g = G1::rand(rng);
    ///     VarMessage::new(g, &message)
    /// };
    ///
    /// let sig = sk.sign(rng, &pp, &var_message);
    /// assert!(pk.verify(&pp, &var_message, &sig));
    /// ```
    pub fn convert(&mut self, p: C::Fr) {
        self.sk.convert(p);
        self.x6 *= p;
        self.x7 *= p;
        self.x8 *= p;
        self.x9 *= p;
        self.x10 *= p;
    }
}
