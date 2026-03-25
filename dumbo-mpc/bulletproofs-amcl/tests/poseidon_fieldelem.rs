use bulletproofs_amcl::poseidon::{PoseidonConfig, PoseidonSponge, find_poseidon_ark_and_mds};
use amcl_wrapper::field_elem::FieldElement;

fn poseidon_parameters_for_test() -> PoseidonConfig {
    let prime_bits = 255;
    let rate: usize = 2;
    let capacity: usize = 1;
    let full_rounds: usize = 8;
    let partial_rounds: usize = 31;
    let skip_matrices: u64 = 0;
    let alpha = 5;

    let (ark, mds) = find_poseidon_ark_and_mds(
        prime_bits,
        rate,
        full_rounds as u64,
        partial_rounds as u64,
        skip_matrices,
    );

    println!("mds len: {}", mds.len());
    println!("mds[0] len: {}", mds[0].len());


    PoseidonConfig::new(full_rounds, partial_rounds, alpha, mds, ark, rate, capacity)
}

#[test]
fn test_poseidon_sponge_amcl() {
    let config = poseidon_parameters_for_test();

    let mut sponge = PoseidonSponge {
        parameters: config.clone(),
        state: vec![FieldElement::zero(); config.rate + config.capacity],
        mode: bulletproofs_amcl::poseidon::DuplexSpongeMode::Absorbing { next_absorb_index: 0 },
    };

    let input1 = FieldElement::from(42u64);
    let input2 = FieldElement::from(2024u64);
    let input3 = FieldElement::from(2024u64);

    sponge.absorb(0, &[input1]);
    sponge.absorb(1, &[input2]);

    sponge.permute();

    sponge.absorb(0, &[input3]);       // 吸收新的输入 input3
    sponge.permute(); 

    let mut out = vec![FieldElement::zero()];
    sponge.squeeze(0, &mut out);

    println!("Poseidon hash: {}", out[0].to_hex());

    // 再做一次相同操作确认一致性
    let rate = config.rate;
    let capacity = config.capacity;
    let mut sponge2 = PoseidonSponge {
        parameters: config,
        state: vec![FieldElement::zero(); rate + capacity],
        mode: bulletproofs_amcl::poseidon::DuplexSpongeMode::Absorbing { next_absorb_index: 0 },
    };

    sponge2.absorb(0, &[FieldElement::from(42u64)]);
    sponge2.absorb(1, &[FieldElement::from(2024u64)]);

    sponge2.permute();

    sponge2.absorb(0, &[FieldElement::from(2024u64)]);    // 吸收新的输入 input3
    sponge2.permute(); 

    let mut out2 = vec![FieldElement::zero()];
    sponge2.squeeze(0, &mut out2);

    println!("Poseidon hash 2: {}", out2[0].to_hex());
    assert_eq!(out[0], out2[0]);
}



