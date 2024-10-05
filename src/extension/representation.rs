use super::signature::VarSignature;
use crate::Curve;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rand_core::RngCore;
use std::ops::Mul;

/// Represents a variable-length message.
#[derive(Clone, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct VarMessage<C>
where
    C: Curve,
{
    pub(crate) g: C::G1,
    pub(crate) u: Vec<C::G1>,
}

impl<C> VarMessage<C>
where
    C: Curve,
{
    /// Return the size (in bytes) of the message.
    pub fn size(&self) -> usize {
        self.g.compressed_size() + self.u.iter().map(|ui| ui.compressed_size()).sum::<usize>()
    }

    /// Return the length of the message (excluding `g`).
    pub fn length(&self) -> usize {
        self.u.len()
    }

    /// Randomize the message.
    /// It is useful when the signer runs a signing protocol with the receiver of the signature.
    /// The signer can give a zero-knowledge proof of original the message, and then signs on the
    /// randomized message to form the signature.
    pub fn randomize(&mut self, w: C::Fr) {
        self.g = self.g.mul(&w);
        self.u = self.u.iter().map(|ui| ui.mul(&w)).collect();
    }

    /// Create vector of tuples Mi = (g, g^i, g^n, h, ui) for calculations in signature signing and verification.
    pub(crate) fn to_tuples(&self, h: C::G1) -> Vec<[C::G1; 5]> {
        let mut gs = Vec::<C::G1>::new();
        let mut gi = self.g;
        for _ in 0..self.u.len() {
            gs.push(gi);
            gi = gi + self.g;
        }
        let gn = gs[gs.len() - 1];
        gs.into_iter()
            .zip(self.u.iter())
            .map(|(gi, ui)| [self.g, gi, gn, h, *ui])
            .collect::<Vec<[C::G1; 5]>>()
    }
}

impl<C> VarMessage<C>
where
    C: Curve,
{
    /// Create a new variable-length message.
    pub fn new(g: C::G1, u: &[C::Fr]) -> Self {
        let u = u.iter().map(|ui| g.mul(ui)).collect();
        VarMessage { g, u }
    }
}

/// Change the representation of the message and the signature.
///
/// ## Example
///
/// ```rust
/// use ark_std::UniformRand;
/// use mercurial_signature::{
///     extension::representation::{VarMessage, change_representation},
///     Curve, CurveBls12_381, PublicParams,
/// };
///
/// type G1 = <CurveBls12_381 as Curve>::G1;
/// type Fr = <CurveBls12_381 as Curve>::Fr;
///
/// let rng = &mut rand::thread_rng();
/// let pp = PublicParams::new(rng);
/// let (pk, sk) = pp.key_gen_ex(rng);
/// let mut var_message = {
///     let message = (0..10).map(|_| Fr::rand(rng)).collect::<Vec<Fr>>();
///     let g = G1::rand(rng);
///     VarMessage::new(g, &message)
/// };
/// let mut sig = sk.sign(rng, &pp, &var_message);
///
/// let u = Fr::rand(rng);
///
/// change_representation(rng, &mut var_message, &mut sig, u);
/// assert!(pk.verify(&pp, &var_message, &sig))
/// ```
pub fn change_representation<C: Curve, R: RngCore>(
    rng: &mut R,
    message: &mut VarMessage<C>,
    signature: &mut VarSignature<C>,
    u: C::Fr,
) {
    let h = signature.h;
    let mut ms = message.to_tuples(h);
    ms.iter_mut()
        .zip(signature.sigs.iter_mut())
        .for_each(|(m, sig)| {
            crate::representation::change_representation(rng, m, sig, u);
        });
    message.g = message.g.mul(&u);
    message.u = message.u.iter().map(|ui| ui.mul(&u)).collect();
    signature.h = h.mul(&u);
}
