use crate::Curve;

use super::representation::VarMessage;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rand_core::RngCore;

#[derive(Clone, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct VarSignature<C>
where
    C: Curve,
{
    pub(crate) h: C::G1,
    pub(crate) sigs: Vec<crate::signature::Signature<C>>,
}

impl<C> VarSignature<C>
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
    /// sk.convert(p);
    /// sig.convert(rng, &mut var_message, p, u);
    /// assert!(pk.verify(&pp, &var_message, &sig))
    /// ```
    pub fn convert<R: RngCore>(
        &mut self,
        rng: &mut R,
        message: &mut VarMessage<C>,
        p: C::Fr,
        u: C::Fr,
    ) {
        super::representation::change_representation(rng, message, self, u);
        self.sigs.iter_mut().for_each(|sig| sig.convert(rng, p));
    }
}
