use crate::{signature::Signature, Curve};
use ark_std::UniformRand;
use rand_core::RngCore;

/// Change the representation of the message and the signature.
///
/// ## Example
///
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
/// let (pk, sk) = pp.key_gen(&mut rng, 10);
/// let mut message = (0..10).map(|_| G1::rand(&mut rng)).collect::<Vec<G1>>();
/// let mut sig = sk.sign(&mut rng, &pp, &message);
///
/// let u = Fr::rand(&mut rng);
/// change_representation(&mut rng, &mut message, &mut sig, u);
/// assert!(pk.verify(&pp, &message, &sig));
/// ```
pub fn change_representation<C: Curve, R: RngCore>(
    rng: &mut R,
    message: &mut [C::G1],
    signature: &mut Signature<C>,
    u: C::Fr,
) {
    let f = C::Fr::rand(rng);
    signature.convert_with_f(u, f);

    message.iter_mut().for_each(|mi| *mi *= u);
}
