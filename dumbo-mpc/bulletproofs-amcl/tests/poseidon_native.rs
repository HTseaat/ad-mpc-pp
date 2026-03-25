use ark_sponge::poseidon::{PoseidonSponge, PoseidonConfig, find_poseidon_ark_and_mds};
use ark_sponge::CryptographicSponge;
use ark_bls12_381::Fr;
use ark_ff::PrimeField;

use ark_bls12_381::G1Affine;
use ark_ec::AffineRepr;
use ark_serialize::CanonicalSerialize;

fn poseidon_parameters_for_test() -> PoseidonConfig<Fr> {
    // Minimal parameter set for quick testing (rate = 2, capacity = 1 ⇒ width = 3)
    let full_rounds = 8;
    let partial_rounds = 57;
    let alpha = 17;
    let rate = 2;          // number of elements absorbed/squeezed per permutation
    let capacity = 1;      // width - rate
    let prime_bits = Fr::MODULUS_BIT_SIZE as u64;

    // Grain‑LFSR helper that deterministically derives round keys & MDS
    let (ark, mds) = find_poseidon_ark_and_mds::<Fr>(
        prime_bits,          // size of the scalar field in bits
        rate,                // sponge rate
        full_rounds as u64,
        partial_rounds as u64,
        0,                   // skip_matrices = 0 ⇒ take the first qualifying MDS
    );

    PoseidonConfig::new(
        full_rounds,
        partial_rounds,
        alpha,
        mds,
        ark,
        rate,
        capacity,
    )
}

#[test]
fn test_poseidon_native() {
    let config = poseidon_parameters_for_test();
    let mut sponge = PoseidonSponge::<Fr>::new(&config);
    sponge.absorb(&Fr::from(42u64));
    sponge.absorb(&Fr::from(2024u64));
    let out: Fr = sponge.squeeze_field_elements(1)[0];
    println!("Poseidon hash: {:?}", out);

    let mut sponge2 = PoseidonSponge::<Fr>::new(&config);
    sponge2.absorb(&Fr::from(42u64));
    sponge2.absorb(&Fr::from(2024u64));
    // let out2 = sponge2.squeeze_field_elements(1)[0];
    let out2: Fr = sponge2.squeeze_field_elements(1)[0];
    println!("Poseidon hash 2: {:?}", out2);
    assert_eq!(out, out2);
}

#[test]
fn test_poseidon_hash_group_element() {
    // 1) 参数
    let config = poseidon_parameters_for_test();

    // 2) 准备要哈希的 G1 点
    let point: G1Affine = G1Affine::generator();

    // 3) 压缩成字节（Vec<u8> 自带 Absorb 实现）
    let mut bytes = Vec::new();
    point
        .serialize_compressed(&mut bytes)
        .expect("serialization should succeed");

    // 4) 计算 Poseidon 哈希
    let mut sponge = PoseidonSponge::<Fr>::new(&config);
    sponge.absorb(&bytes);
    let digest1: Fr = sponge.squeeze_field_elements(1)[0];
    println!("Poseidon hash of G1 point: {:?}", digest1);

    // 5) 再算一次，验证确定性
    let mut sponge2 = PoseidonSponge::<Fr>::new(&config);
    sponge2.absorb(&bytes);
    let digest2: Fr = sponge2.squeeze_field_elements(1)[0];

    assert_eq!(digest1, digest2);
}