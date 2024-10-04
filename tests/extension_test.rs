use ark_std::UniformRand;
use mercurial_signature::{
    extension::representation::{change_representation, VarMessage},
    Curve, CurveBls12_381, PublicParams,
};

type G1 = <CurveBls12_381 as Curve>::G1;
type Fr = <CurveBls12_381 as Curve>::Fr;

/// Test the conversion function for the public key, secret key, and signature.
/// The converted public key, secret key, and signature should be able to verify the message.
#[test]
fn verify_ok_for_original_message_with_converted_keys_and_sigs() {
    let rng = &mut rand::thread_rng();
    let pp = PublicParams::new(rng);
    let (pk, sk) = pp.key_gen_ex(rng);

    let var_message = random_varmessage(rng);
    let sig = sk.sign(rng, &pp, &var_message);

    let p = Fr::rand(rng);
    let u = Fr::rand(rng);

    let mut pk2 = pk.clone();
    pk2.convert(p);
    assert!(pk != pk2);

    let mut sk2 = sk.clone();
    sk2.convert(p);
    assert!(sk != sk2);

    let mut sig2 = sig.clone();
    let mut message2 = var_message.clone();
    sig2.convert(rng, &mut message2, p, u);
    assert!(sig != sig2);

    // The converted public key, secret key, and signature should be able to verify the message.
    assert!(pk2.verify(&pp, &message2, &sig2));

    // The converted secret key should be able to sign the message.
    let sig3 = sk2.sign(rng, &pp, &var_message);
    assert!(pk2.verify(&pp, &var_message, &sig3));
}

/// Test the conversion function for the public key, secret key, and signature.
/// The converted public key and secret key should be able to sign and verify the message.
#[test]
fn verify_ok_with_converted_keys() {
    let rng = &mut rand::thread_rng();
    let pp = PublicParams::new(rng);
    let (pk, sk) = pp.key_gen_ex(rng);

    let p = Fr::rand(rng);

    let mut pk2 = pk.clone();
    pk2.convert(p);
    assert!(pk != pk2);

    let mut sk2 = sk.clone();
    sk2.convert(p);
    assert!(sk != sk2);

    // verify the converted public key and secret key can sign and verify the message
    let var_message = random_varmessage(rng);
    let sig2 = sk2.sign(rng, &pp, &var_message);
    assert!(pk2.verify(&pp, &var_message, &sig2));
}

/// Test the conversion function for the public key and secret key.
/// The converted key should not be able to verify the message with another unconverted key.
#[test]
fn verify_fail_if_key_is_not_converted() {
    let rng = &mut rand::thread_rng();
    let pp = PublicParams::new(rng);
    let (pk, sk) = pp.key_gen_ex(rng);

    let p = Fr::rand(rng);

    let mut pk2 = pk.clone();
    pk2.convert(p);
    assert!(pk != pk2);

    let mut sk2 = sk.clone();
    sk2.convert(p);
    assert!(sk != sk2);

    let var_message = random_varmessage(rng);

    // use sk to sign and pk2 to verify
    let sig = sk2.sign(rng, &pp, &var_message);
    assert!(!pk.verify(&pp, &var_message, &sig));

    // use sk2 to sign and pk to verify
    let sig2 = sk.sign(rng, &pp, &var_message);
    assert!(!pk2.verify(&pp, &var_message, &sig2));
}

/// Test the conversion function for the public key, secret key, and signature.
/// The converted public key, secret key should not be able to verify the message
/// with the original signature.
#[test]
fn verify_fail_if_signature_is_not_converted() {
    let rng = &mut rand::thread_rng();
    let pp = PublicParams::new(rng);
    let (pk, sk) = pp.key_gen_ex(rng);
    let var_message = random_varmessage(rng);
    let sig = sk.sign(rng, &pp, &var_message);

    let p = Fr::rand(rng);

    let mut pk2 = pk.clone();
    pk2.convert(p);
    assert!(pk != pk2);

    // use the converted keys to verify the original signature
    assert!(!pk2.verify(&pp, &var_message, &sig));
}

/// Test the conversion function works with the change representation function.
#[test]
fn verify_ok_with_conversion_and_then_change_representation() {
    let rng = &mut rand::thread_rng();
    let pp = PublicParams::new(rng);
    let (mut pk, mut sk) = pp.key_gen_ex(rng);
    let mut var_message = random_varmessage(rng);
    let mut sig = sk.sign(rng, &pp, &var_message);

    let p = Fr::rand(rng);
    let u = Fr::rand(rng);

    pk.convert(p);
    sk.convert(p);
    sig.convert(rng, &mut var_message, p, u);

    let u2 = Fr::rand(rng);
    change_representation(rng, &mut var_message, &mut sig, u2);
    assert!(pk.verify(&pp, &var_message, &sig));
}

#[test]
fn verify_ok_with_change_representation_and_then_conversion() {
    let rng = &mut rand::thread_rng();
    let pp = PublicParams::new(rng);
    let (mut pk, mut sk) = pp.key_gen_ex(rng);
    let mut var_message = random_varmessage(rng);
    let mut sig = sk.sign(rng, &pp, &var_message);

    let u = Fr::rand(rng);
    change_representation(rng, &mut var_message, &mut sig, u);

    let p = Fr::rand(rng);
    let u2 = Fr::rand(rng);
    pk.convert(p);
    sk.convert(p);
    sig.convert(rng, &mut var_message, p, u2);
    assert!(pk.verify(&pp, &var_message, &sig));
}

/// Test the change representation function -
/// 1. The original message and changed signature should not be able to verify.
/// 2. The changed message and original signature should not be able to verify.
#[test]
fn verify_fail_if_representation_has_not_changed() {
    let rng = &mut rand::thread_rng();
    let pp = PublicParams::new(rng);
    let (pk, sk) = pp.key_gen_ex(rng);
    let var_message = random_varmessage(rng);
    let sig = sk.sign(rng, &pp, &var_message);

    let mut var_message2 = var_message.clone();
    let mut sig2 = sig.clone();
    let u = Fr::rand(rng);
    change_representation(rng, &mut var_message2, &mut sig2, u);

    // verify the original message and changed signature
    assert!(!pk.verify(&pp, &var_message2, &sig));
    // verify the changed message and original signature
    assert!(!pk.verify(&pp, &var_message, &sig2));
}

fn random_varmessage(rng: &mut impl rand_core::RngCore) -> VarMessage<CurveBls12_381> {
    let message = (0..10).map(|_| Fr::rand(rng)).collect::<Vec<Fr>>();
    let g = G1::rand(rng);
    VarMessage::new(g, &message)
}
