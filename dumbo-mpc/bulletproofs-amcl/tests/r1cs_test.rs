extern crate merlin;
extern crate bulletproofs_amcl;
use bulletproofs_amcl as bulletproofs;

use bulletproofs::r1cs::{ConstraintSystem, LinearCombination, Prover, Variable, Verifier};
use amcl_wrapper::field_elem::FieldElement;
use amcl_wrapper::group_elem::GroupElement;
use amcl_wrapper::group_elem_g1::{G1Vector, G1};
use bulletproofs::utils::get_generators;
use merlin::Transcript;
use amcl_wrapper::group_elem::GroupElementVector; // 确保导入 trait
use hex;



#[test]
fn test_2_factors_r1cs() {
    // Prove knowledge of `p` and `q` such that given an `r`, `p * q = r`
    let G: G1Vector = get_generators("G", 8).into();
    let H: G1Vector = get_generators("H", 8).into();
    // let g = G1::from_msg_hash("g".as_bytes());
    // let h = G1::from_msg_hash("h".as_bytes());

    let uncompressed_hex_g = "0417f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1";  // 用 Python 打印出来的 hex
    let bytes_g = hex::decode(uncompressed_hex_g).unwrap();
    let g = G1::from_bytes(&bytes_g).unwrap();

    let uncompressed_hex_h = "041928f3beb93519eecf0145da903b40a4c97dca00b21f12ac0df3be9116ef2ef27b2ae6bcd4c5bc2d54ef5a70627efcb7108dadbaa4b636445639d5ae3089b3c43a8a1d47818edd1839d7383959a41c10fdc66849cfa1b08c5a11ec7e28981a1c";  // 用 Python 打印出来的 hex
    let bytes_h = hex::decode(uncompressed_hex_h).unwrap();
    let h = G1::from_bytes(&bytes_h).unwrap();

    println!("g = {:?}", g);
    println!("h = {:?}", h);

    // println!("G vector:");
    // for (i, g_i) in G.iter().enumerate() {
    //     println!("G[{}] = {:?}", i, g_i);
    // }

    let mut factors = vec![
        (
            FieldElement::from_hex("1ab3ce638d5bdd7c3ae1c6a18fea44276b91d6ef3ad263a4d3a6d0147744453c".to_string()).unwrap(),
            FieldElement::from_hex("bc3e8cba8c1f37460d429fe302816f7821a18b54d625bb5814239ba62129cc7".to_string()).unwrap(),
            FieldElement::from_hex("2fc7b463304123935960a640d4a08f27a800debc80680450cface8fdd354844b".to_string()).unwrap(),
        ),
        (
            FieldElement::from(7u32),
            FieldElement::from(5u32),
            FieldElement::from(35u32),
        ),
    ];

    let (proof, mut commitments) = {
        let mut comms = vec![];
        let mut prover_transcript = Transcript::new(b"Factors");
        let mut prover = Prover::new(&g, &h, &mut prover_transcript);

        for (p, q, r) in &factors {
            // let (com_p, var_p) = prover.commit(p.clone(), FieldElement::random());
            // let (com_q, var_q) = prover.commit(q.clone(), FieldElement::random());
            let (com_p, var_p) = prover.commit(p.clone(), p.clone());
            let (com_q, var_q) = prover.commit(q.clone(), q.clone());
            let (_, _, o) = prover.multiply(var_p.into(), var_q.into());
            // let lc: LinearCombination = vec![(Variable::One(), r.clone())].iter().collect();
            // prover.constrain(o - lc);
            // let (com_r, var_r) = prover.commit(r.clone(), FieldElement::random());
            let (com_r, var_r) = prover.commit(r.clone(), r.clone());
            prover.constrain(o - var_r);
            // prover.constrain(o.into() - lc);
            comms.push(com_p);
            comms.push(com_q);
            comms.push(com_r);
        }

        let proof = prover.prove(&G, &H).unwrap();

        (proof, comms)
    };

    println!("Proving done");

    let mut verifier_transcript = Transcript::new(b"Factors");
    let mut verifier = Verifier::new(&mut verifier_transcript);
    for _ in factors.drain(0..) {
    // for (_, _, r) in factors.drain(0..) {
        let var_p = verifier.commit(commitments.remove(0));
        let var_q = verifier.commit(commitments.remove(0));
        let (_, _, o) = verifier.multiply(var_p.into(), var_q.into());
        // let lc: LinearCombination = vec![(Variable::One(), r)].iter().collect();
        // verifier.constrain(o - lc);
        let var_r = verifier.commit(commitments.remove(0));
        verifier.constrain(o - var_r);
    }

    println!("Starting verification...");
    assert!(verifier.verify(&proof, &g, &h, &G, &H).is_ok());
    println!("Verification passed.");
}

#[test]
fn test_factor_r1cs() {
    // Prove knowledge of `p` and `q` such that given an `r`, `p * q = r`
    let G: G1Vector = get_generators("G", 8).into();
    let H: G1Vector = get_generators("H", 8).into();
    let g = G1::from_msg_hash("g".as_bytes());
    let h = G1::from_msg_hash("h".as_bytes());

    let mut factors = vec![
        (
            FieldElement::from(2u32),
            FieldElement::from(4u32),
            FieldElement::from(6u32),
            FieldElement::from(48u32),
        ),
        (
            FieldElement::from(7u32),
            FieldElement::from(5u32),
            FieldElement::from(35u32),
            FieldElement::from(1225u32),
        ),
    ];

    let (proof, mut commitments) = {
        let mut comms = vec![];
        let mut prover_transcript = Transcript::new(b"Factors");
        let mut prover = Prover::new(&g, &h, &mut prover_transcript);

        for (p, q, r, s) in &factors {
            let (com_p, var_p) = prover.commit(p.clone(), FieldElement::random());
            let (com_q, var_q) = prover.commit(q.clone(), FieldElement::random());
            let (com_r, var_r) = prover.commit(r.clone(), FieldElement::random());
            let (_, _, o1) = prover.multiply(var_p.into(), var_q.into());
            let (_, _, o2) = prover.multiply(o1.into(), var_r.into());
            let lc: LinearCombination = vec![(Variable::One(), s.clone())].iter().collect();
            prover.constrain(o2 - lc);
            comms.push(com_p);
            comms.push(com_q);
            comms.push(com_r);
        }

        let proof = prover.prove(&G, &H).unwrap();

        (proof, comms)
    };

    println!("Proving done");

    let mut verifier_transcript = Transcript::new(b"Factors");
    let mut verifier = Verifier::new(&mut verifier_transcript);
    for (_, _, _, s) in factors.drain(0..) {
        let var_p = verifier.commit(commitments.remove(0));
        let var_q = verifier.commit(commitments.remove(0));
        let var_r = verifier.commit(commitments.remove(0));
        let (_, _, o1) = verifier.multiply(var_p.into(), var_q.into());
        let (_, _, o2) = verifier.multiply(o1.into(), var_r.into());
        let lc: LinearCombination = vec![(Variable::One(), s)].iter().collect();
        verifier.constrain(o2 - lc);
    }

    assert!(verifier.verify(&proof, &g, &h, &G, &H).is_ok());
}
