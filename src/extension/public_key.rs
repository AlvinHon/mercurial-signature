use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use crate::{params::PublicParams, Curve};

use super::{representation::VarMessage, signature::VarSignature};
use std::ops::Mul;

#[derive(Clone, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct PublicKey<C>
where
    C: Curve,
{
    // public key with length = 5. i.e. (bx1, bx2, bx3, bx4, bx5) = (p2^x1, p2^x2, p2^x3, p2^x4, p2^x5)
    pub(crate) pk: crate::public_key::PublicKey<C>,

    // TODO These variables are used in signing protocol - to verify if the
    // glue element h is computed correctly by signer's zero-knowledge proof.
    pub(crate) _bx6: C::G2,
    pub(crate) _bx7: C::G2,
    pub(crate) _bx8: C::G2,
    pub(crate) _bx9: C::G2,
    pub(crate) _bx10: C::G2,
}

impl<C> PublicKey<C>
where
    C: Curve,
{
    /// Verify a variable-length message.
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
    pub fn verify(
        &self,
        pp: &PublicParams<C>,
        message: &VarMessage<C>,
        signature: &VarSignature<C>,
    ) -> bool {
        // Mi = (g, g^i, g^n, h, ui)
        let ms = message.to_tuples(signature.h);
        signature
            .sigs
            .iter()
            .zip(ms)
            .all(|(sig, m)| self.pk.verify(pp, &m, sig))
    }

    /// Convert the public key.
    /// This function converts the public key to a new public key that is equivalent to the original public key.
    /// The input scalar `p` must be the same as the one used in the conversion of the secret key and the signature.
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
    /// let (mut pk, sk) = pp.key_gen_ex(rng);
    ///
    /// let mut var_message = {
    ///     let message = (0..10).map(|_| Fr::rand(rng)).collect::<Vec<Fr>>();
    ///     let g = G1::rand(rng);
    ///     VarMessage::new(g, &message)
    /// };
    /// let mut sig = sk.sign(rng, &pp, &var_message);
    ///
    /// let p = Fr::rand(rng);
    /// let u = Fr::rand(rng);
    /// pk.convert(p);
    /// sig.convert(rng, &mut var_message, p, u);
    /// assert!(pk.verify(&pp, &var_message, &sig))
    /// ```
    pub fn convert(&mut self, p: C::Fr) {
        self.pk.convert(p);
        self._bx6 = self._bx6.mul(&p);
        self._bx7 = self._bx7.mul(&p);
        self._bx8 = self._bx8.mul(&p);
        self._bx9 = self._bx9.mul(&p);
        self._bx10 = self._bx10.mul(&p);
    }
}
