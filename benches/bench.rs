use std::time::Duration;

use ark_serialize::CanonicalSerialize;
use ark_std::{test_rng, UniformRand};
use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use mercurial_signature::{
    extension::{self},
    Curve, CurveBls12_381, PublicKey, PublicParams, SecretKey,
};
use rand::Rng;

type G1 = <CurveBls12_381 as Curve>::G1;
type Fr = <CurveBls12_381 as Curve>::Fr;

criterion_group! {
    name = signature;
    config = Criterion::default().sample_size(10).measurement_time(Duration::from_secs(2));
    targets = bench_sign, bench_verify,
}

criterion_group! {
    name = signature_extension;
    config = Criterion::default().sample_size(10).measurement_time(Duration::from_secs(2));
    targets = bench_sign_ex, bench_verify_ex,
}

criterion_main!(signature, signature_extension,);

fn bench_sign(c: &mut Criterion) {
    let mut rng = test_rng();

    let mut group = c.benchmark_group("bench_sign");
    for size in [10, 100, 1000] {
        let (pp, _, sk, message) = setup(&mut rng, size);

        let message_size = message.iter().map(|m| m.compressed_size()).sum::<usize>();
        group.throughput(Throughput::Bytes(message_size as u64));

        group.bench_with_input(format!("size={}", size), &size, |b, _| {
            b.iter(|| sk.sign(&mut rng, &pp, &message.as_ref()))
        });
    }
}

fn bench_verify(c: &mut Criterion) {
    let mut rng = test_rng();

    let mut group = c.benchmark_group("bench_verify");
    for size in [10, 100, 1000] {
        let (pp, pk, sk, message) = setup(&mut rng, size);
        let sig = sk.sign(&mut rng, &pp, &message);

        let message_size = message.iter().map(|m| m.compressed_size()).sum::<usize>();
        group.throughput(Throughput::Bytes(message_size as u64));

        group.bench_with_input(format!("size={}", size), &size, |b, _| {
            b.iter(|| pk.verify(&pp, &message.as_ref(), &sig))
        });
    }
}

fn bench_sign_ex(c: &mut Criterion) {
    let mut rng = test_rng();

    let mut group = c.benchmark_group("bench_sign_ex");

    for size in [10, 100] {
        let (pp, _, sk, message) = setup_ex(&mut rng, size);

        let message_size = message.size();
        group.throughput(Throughput::Bytes(message_size as u64));

        group.bench_with_input(format!("size={}", size), &size, |b, _| {
            b.iter(|| sk.sign(&mut rng, &pp, &message))
        });
    }
}

fn bench_verify_ex(c: &mut Criterion) {
    let mut rng = test_rng();

    let mut group = c.benchmark_group("bench_verify_ex");

    for size in [10, 100] {
        let (pp, pk, sk, message) = setup_ex(&mut rng, size);
        let sig = sk.sign(&mut rng, &pp, &message);

        let message_size = message.size();
        group.throughput(Throughput::Bytes(message_size as u64));

        group.bench_with_input(format!("size={}", size), &size, |b, _| {
            b.iter(|| pk.verify(&pp, &message, &sig))
        });
    }
}

fn setup(rng: &mut impl Rng, size: u32) -> (PublicParams, PublicKey, SecretKey, Vec<G1>) {
    let pp = PublicParams::new(rng);
    let (pk, sk) = pp.key_gen(rng, size);
    let message = (0..size).map(|_| G1::rand(rng)).collect::<Vec<G1>>();
    (pp, pk, sk, message)
}

fn setup_ex(
    rng: &mut impl Rng,
    size: u32,
) -> (
    PublicParams,
    extension::PublicKey<CurveBls12_381>,
    extension::SecretKey<CurveBls12_381>,
    extension::representation::VarMessage<CurveBls12_381>,
) {
    let pp = PublicParams::new(rng);
    let (pk, sk) = pp.key_gen_ex(rng);
    let message = {
        let message = (0..size).map(|_| Fr::rand(rng)).collect::<Vec<Fr>>();
        let g = G1::rand(rng);
        extension::representation::VarMessage::new(g, &message)
    };
    (pp, pk, sk, message)
}
