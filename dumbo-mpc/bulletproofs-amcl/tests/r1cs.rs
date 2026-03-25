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

use ark_sponge::poseidon::{find_poseidon_ark_and_mds, PoseidonConfig, PoseidonSponge};
use ark_sponge::CryptographicSponge;
use ark_ff::{PrimeField, BigInteger, Field};
use ark_bls12_381::Fr as ArkFr;
use ark_serialize::CanonicalSerialize;
use ark_ff::Zero;
use ark_sponge::FieldBasedCryptographicSponge;
use ark_bls12_381::Fq as ArkFq;

use std::time::Instant;

/// 打印 Arkworks 的 state 向量（Vec<Fr>）为 32字节 Hex 字符串
fn print_poseidon_state_hex(label: &str, state: &Vec<ArkFq>) {
    println!("{}:", label);
    for (i, elem) in state.iter().enumerate() {
        let hex_str = elem
            .into_bigint()
            .to_bytes_be()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>();
        println!("  state[{}] = {}", i, hex_str);
    }
}

/// Minimal Poseidon 参数 (rate=2, capacity=1)
fn poseidon_parameters_for_test() -> PoseidonConfig<ArkFq> {
    // Minimal parameter set for quick testing (rate = 2, capacity = 1 ⇒ width = 3)
    let full_rounds = 8;
    let partial_rounds = 57;
    let alpha = 5;
    let rate = 2;          // number of elements absorbed/squeezed per permutation
    let capacity = 1;      // width - rate
    let prime_bits = ArkFq::MODULUS_BIT_SIZE as u64;

    // Grain‑LFSR helper that deterministically derives round keys & MDS
    let (ark, mds) = find_poseidon_ark_and_mds::<ArkFq>(
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

/// 使用 Poseidon 参数在 R1CS 中构造哈希约束
pub fn poseidon_permute_r1cs<CS: ConstraintSystem>(
    cs: &mut CS,
    state: &mut Vec<LinearCombination>,
    config: &PoseidonConfig<ark_bls12_381::Fq>,
    ark_fe: &Vec<Vec<FieldElement>>,
    mds_fe: &Vec<Vec<FieldElement>>,
) {
    let width = config.rate + config.capacity;
    let half_full = config.full_rounds / 2;
    let total_rounds = config.full_rounds + config.partial_rounds;

    for round_idx in 0..total_rounds {
        let round_constants_fe = &ark_fe[round_idx];
        let is_full_round =
            round_idx < half_full || round_idx >= half_full + config.partial_rounds;

        // ---------- S-box ----------
        let mut after_sbox = Vec::with_capacity(width);
        for i in 0..width {
            let mut lc = LinearCombination::default();
            lc += round_constants_fe[i].clone() * Variable::One();
            lc += state[i].clone();
            let (_, _, lc_var) = cs.multiply(lc.into(), Variable::One().into());

            if is_full_round || i == 0 {
                let mut pow_var = lc_var;
                for _ in 0..(config.alpha - 1) {
                    let (_, _, next) = cs.multiply(pow_var.into(), lc_var.into());
                    pow_var = next;
                }
                after_sbox.push(pow_var);
            } else {
                after_sbox.push(lc_var);
            }
        }

        // ---------- MDS ----------
        let mut next_state = Vec::with_capacity(width);
        for j in 0..width {
            let mut mds_lc = LinearCombination::default();
            for k in 0..width {
                mds_lc += mds_fe[j][k].clone() * after_sbox[k];
            }
            let (_, _, mds_var) = cs.multiply(mds_lc.into(), Variable::One().into());
            next_state.push(mds_var.into());
        }

        *state = next_state;
    }
}

/// 仅用于调试，完全照 Arkworks 逻辑在 Fr 上跑
fn poseidon_permute_simulate_native_fr(
    state: &mut [ArkFq],               // 直接用 ArkFq
    cfg: &PoseidonConfig<ArkFq>,
) {
    let w      = cfg.rate + cfg.capacity;
    let half   = cfg.full_rounds / 2;
    let total  = cfg.full_rounds + cfg.partial_rounds;

    for r in 0..total {
        let full = r < half || r >= half + cfg.partial_rounds;

        // 1. ARK
        for i in 0..w {
            state[i] += cfg.ark[r][i];
        }
        // 2. S-Box
        if full {
            for s in state.iter_mut() {
                *s = s.pow(&[cfg.alpha]);
            }
        } else {
            state[0] = state[0].pow(&[cfg.alpha]);
        }
        // 3. MDS
        let mut next = vec![ArkFq::zero(); w];
        for j in 0..w {
            for k in 0..w {
                next[j] += state[k] * cfg.mds[j][k];
            }
        }
        state.copy_from_slice(&next);
    }
}

fn poseidon_permute_simulate_native(
    state: &mut Vec<FieldElement>,
    config: &PoseidonConfig<ArkFq>,
    ark_fe: &Vec<Vec<FieldElement>>,
    mds_fe: &Vec<Vec<FieldElement>>,
) {
    let width = config.rate + config.capacity;
    let half_full = config.full_rounds / 2;
    let total_rounds = config.full_rounds + config.partial_rounds;
    let alpha = config.alpha as u64;

    for round_idx in 0..total_rounds {
        let is_full_round =
            round_idx < half_full || round_idx >= half_full + config.partial_rounds;

        // 1. Apply ARK
        for i in 0..width {
            state[i] = &state[i] + &ark_fe[round_idx][i];
        }

        // 2. Apply S-box
        for i in 0..width {
            if is_full_round || i == 0 {
                state[i] = state[i].pow(&FieldElement::from(alpha));
            }
        }

        // 3. Apply MDS
        let mut new_state = vec![FieldElement::zero(); width];
        for j in 0..width {
            for k in 0..width {
                new_state[j] = &new_state[j] + &(&mds_fe[j][k] * &state[k]);
            }
        }

        *state = new_state;
    }
}

fn convert_arkfq_to_field_element(fe: ArkFq) -> FieldElement {
    // 1. 转成 BigInteger → 得到 big-endian 字节
    let mut be_bytes = fe.into_bigint().to_bytes_be();
    // ⚠️ AMCL expects little-endian bytes, so reverse!
    be_bytes.reverse();

    let mut padded = [0u8; 48];
    padded[..be_bytes.len()].copy_from_slice(&be_bytes);

    // // 2. 填充到 48 字节（AMCL FieldElement 大小）
    // let mut padded = [0u8; 48];
    // padded[48 - be_bytes.len()..].copy_from_slice(&be_bytes);

    // 3. 转成 AMCL FieldElement
    FieldElement::from_bytes(&padded).unwrap()
}



fn convert_arkfq_to_amcl_fe(native_out: ArkFq) -> FieldElement {
    // 将 Montgomery 域元素转为正常模域表示
    let repr = native_out.into_bigint();  // Still Montgomery-represented
    let canonical = ArkFq::from_bigint(repr).unwrap(); // This converts to canonical Fq

    // 再转为标准 BigInt，再提取字节
    let canonical_bytes = canonical.into_bigint().to_bytes_be();

    // 转为 AMCL 格式（48字节）
    let mut padded = [0u8; 48];
    padded[48 - canonical_bytes.len()..].copy_from_slice(&canonical_bytes);
    FieldElement::from_bytes(&padded).unwrap()
}

#[test]
fn test_poseidon_hash_r1cs_manual() {

    


    // 创建一个 FieldElement，比如取 42
    let fe = FieldElement::from(42u64);

    // 转为字节表示
    let bytes = fe.to_bytes();

    // 打印字节长度和内容
    println!("FieldElement byte length = {}", bytes.len());
    println!("FieldElement bytes = {:?}", bytes);

    // 1. 本地 native 输出
    let config = poseidon_parameters_for_test();
    let mut native = PoseidonSponge::<ArkFq>::new(&config);
    let input = ArkFq::from(42u64);
    native.absorb(&input);
    let input = ArkFq::from(0u64);
    native.absorb(&input);
    // let native_out: ArkFq = native.squeeze_field_elements(1)[0];
    let native_outs = native.squeeze_native_field_elements(1);
    for (i, elem) in native_outs.iter().enumerate() {
        println!("native.squeeze_native_field_elements({})[{}] = {}", native_outs.len(), i, elem.to_string());
    }

    // ✅ 只从第一次调用的结果中取值！
    let native_out: ArkFq = native_outs[0];
    let fe_native = convert_arkfq_to_field_element(native_out);
    println!("fe_native 0 = {}", fe_native.to_hex());

    let bytes = fe_native.to_bytes(); // little-endian

    // 转成 ArkFq 比较（用 from_le_bytes_mod_order）
    let ark_from_amcl = ArkFq::from_le_bytes_mod_order(&bytes);
    println!("ark_from_amcl = {}", ark_from_amcl);

    // let fe = convert_arkfq_to_amcl_fe(native_out);
    // let bytes = fe.to_bytes();
    // let fq_roundtrip = ArkFq::from_le_bytes_mod_order(&bytes);  // 注意 AMCL 是 LE
    // assert_eq!(fq_roundtrip, native_out);  // ✅ 成功的话表示互通正确

    let start = Instant::now();

    // Convert native_out (ArkFq) to AMCL FieldElement for committing
    // AMCL `from_bytes` expects big‑endian representation, so we must feed BE bytes.
    let fe_native = {
        // 1. 获取大端序字节
        let mut be_repr = native_out.into_bigint().to_bytes_be();
        // 如果你想打印为十六进制：
        let hex_str = be_repr.iter().map(|b| format!("{:02x}", b)).collect::<String>();
        println!("be_repr (hex) = {}", hex_str);
        // 2. 填充到 48 字节（AMCL Fq 大小）
        let mut padded = [0u8; 48];
        padded[48 - be_repr.len()..].copy_from_slice(&be_repr);
        println!("AMCL FieldElement (BE padded bytes) = {:?}", padded);
        FieldElement::from_bytes(&be_repr).unwrap()
    };

    println!("native_out (ArkFq) = {}", native_out);

    let hex_str = "17bad24a018acdd3c932eba30ca3e257e5562a2084b91bb2a103cf374c844e6edc86ac84a643683b4d63d665ac4212f4";
    let bytes = hex::decode(hex_str).unwrap();
    let mut padded = [0u8; 48];
    padded.copy_from_slice(&bytes); // already是48字节
    let fe = FieldElement::from_bytes(&padded).unwrap();


    println!("fe = {}", fe);

    // 反过来，从 AMCL 的 FieldElement 拿出字节
    let bytes = fe.to_bytes(); // little-endian

    // 转成 ArkFq 比较（用 from_le_bytes_mod_order）
    let ark_from_amcl = ArkFq::from_le_bytes_mod_order(&bytes);
    println!("ark_from_amcl = {}", ark_from_amcl);
    let amcl_bytes = fe.to_bytes(); // AMCL: likely little-endian
    println!("AMCL bytes = {:?}", amcl_bytes);

    let ark_be = native_out.into_bigint().to_bytes_be();
    println!("ArkFq BE bytes = {:?}", ark_be);
    assert_eq!(ark_from_amcl, native_out);
    

    // 打印 ArkFq 的字节表示
    let mut repr_check = Vec::new();
    native_out.serialize_uncompressed(&mut repr_check).unwrap();
    println!("ArkFq serialized bytes = {:?}", repr_check);

    // 打印转换后的 AMCL FieldElement 的字节表示
    println!("fe_native (AMCL) = {}", fe_native.to_hex()); // 如果支持 `.to_hex()`
    // println!("fe_native (AMCL) = {}", fe_native); // 如果支持 `.to_hex()`

    // let fe = FieldElement::from(42u64);
    // let bytes = fe.to_bytes();
    // println!("bytes = {:?}", bytes);
    // println!("length = {}", bytes.len()); // 应为 48

    // let hex_str = fe.to_hex();
    // println!("hex = {}", hex_str);

    // Convert Arkworks Poseidon parameters (ArkFq) to AMCL FieldElement
    use ark_ff::BigInteger;

    let ark_fe: Vec<Vec<FieldElement>> = config.ark.iter().map(|round| {
        round.iter().map(|rc| {
            let bytes = rc.into_bigint().to_bytes_be();
            let mut be = [0u8; 48];
            be[48 - bytes.len()..].copy_from_slice(&bytes);
            FieldElement::from_bytes(&be).unwrap()
        }).collect()
    }).collect();
    let mds_fe: Vec<Vec<FieldElement>> = config.mds.iter().map(|row| {
        row.iter().map(|e| {
            let bytes = e.into_bigint().to_bytes_be();
            let mut be = [0u8; 48];
            be[48 - bytes.len()..].copy_from_slice(&bytes);
            FieldElement::from_bytes(&be).unwrap()
        }).collect()
    }).collect();

    // 验证转换是否保留原值
    let rc_orig = config.ark[0][0];
    let bytes = rc_orig.into_bigint().to_bytes_be();
    let mut be = [0u8; 48];
    be[48 - bytes.len()..].copy_from_slice(&bytes);
    let rc_amcl = FieldElement::from_bytes(&be).unwrap();


    println!("==== Arkworks config.ark (Fr) ====");
    for (round_idx, round) in config.ark.iter().enumerate() {
        for (i, elem) in round.iter().enumerate() {
            let hex = elem
                .into_bigint()
                .to_bytes_be()
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>();
            println!("ark[{}][{}] = {}", round_idx, i, hex);
        }
    }

    println!("==== Converted ark_fe (AMCL FieldElement) ====");
    for (round_idx, round) in ark_fe.iter().enumerate() {
        for (i, elem) in round.iter().enumerate() {
            println!("ark_fe[{}][{}] = {}", round_idx, i, elem.to_hex());
        }
    }

    println!("==== Arkworks config.mds (Fr) ====");
    for (row_idx, row) in config.mds.iter().enumerate() {
        for (i, elem) in row.iter().enumerate() {
            let hex = elem
                .into_bigint()
                .to_bytes_be()
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>();
            println!("mds[{}][{}] = {}", row_idx, i, hex);
        }
    }

    println!("==== Converted mds_fe (AMCL FieldElement) ====");
    for (row_idx, row) in mds_fe.iter().enumerate() {
        for (i, elem) in row.iter().enumerate() {
            println!("mds_fe[{}][{}] = {}", row_idx, i, elem.to_hex());
        }
    }

    // 结束计时
    let duration = start.elapsed();
    println!("Conversion time (ArkFq → FieldElement): {:?}", duration);

    // 2. 初始化 Prover
    // // Compute number of multiplication gates: (total rounds * width * (alpha + 1))
    // let rounds = config.ark.len(); // total number of Poseidon rounds
    // let width = (config.rate + config.capacity) as usize;
    // let num_mults = rounds * width * (config.alpha as usize + 1);
    // println!("num_mults = {:?}", num_mults);
    // let G: G1Vector = get_generators("G", num_mults).into();
    // let H: G1Vector = get_generators("H", num_mults).into();
    // Hardcoded to the next power-of-two >= required multiplications
    // 生成这些非常耗时，在实际部署的时候可以先提前生成然后缓存下来，生成大概需要 18s
    let start_gens = Instant::now();
    let G: G1Vector = get_generators("G", 4096).into();
    let H: G1Vector = get_generators("H", 4096).into();
    println!("Generator generation time: {:?}", start_gens.elapsed());
    let uncompressed_hex_g = "0417f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1";  // 用 Python 打印出来的 hex
    let bytes_g = hex::decode(uncompressed_hex_g).unwrap();
    let g = G1::from_bytes(&bytes_g).unwrap();

    let uncompressed_hex_h = "041928f3beb93519eecf0145da903b40a4c97dca00b21f12ac0df3be9116ef2ef27b2ae6bcd4c5bc2d54ef5a70627efcb7108dadbaa4b636445639d5ae3089b3c43a8a1d47818edd1839d7383959a41c10fdc66849cfa1b08c5a11ec7e28981a1c";  // 用 Python 打印出来的 hex
    let bytes_h = hex::decode(uncompressed_hex_h).unwrap();
    let h = G1::from_bytes(&bytes_h).unwrap();

    // println!("g = {:?}", g);
    // println!("h = {:?}", h);

    let mut prover_transcript = Transcript::new(b"Poseidon");
    let mut prover = Prover::new(&g, &h, &mut prover_transcript);

    

    // 3. Commit inputs (rate=2, capacity=1)
    // let (com_x0, var_x0) = prover.commit(FieldElement::from(42u64), FieldElement::random());
    // let (com_x1, var_x1) = prover.commit(FieldElement::zero(), FieldElement::random());
    // let (com_c, var_c)  = prover.commit(FieldElement::zero(), FieldElement::random());
    // let mut state: Vec<LinearCombination> = vec![var_x0.into(), var_x1.into(), var_c.into()];
    let (com_c, var_c)  = prover.commit(FieldElement::zero(), FieldElement::random());
    let (com_x0, var_x0) = prover.commit(FieldElement::from(42u64), FieldElement::random());
    let (com_x1, var_x1) = prover.commit(FieldElement::zero(), FieldElement::random());
    let mut state: Vec<LinearCombination> = vec![var_c.into(), var_x0.into(), var_x1.into()];

    // 4. 构建 S-box + MDS 约束 —— 正确处理 full‑round 与 partial‑round
    // poseidon_permute_r1cs(&mut prover, &mut state, &config, &ark_fe, &mds_fe);

    let mut test_state = vec![
        FieldElement::zero(),
        FieldElement::from(42u64),
        FieldElement::zero(),
    ];
    poseidon_permute_simulate_native(&mut test_state, &config, &ark_fe, &mds_fe);
    println!(
        "Simulated Poseidon output = {}",
        test_state[config.capacity].to_hex()
    );
    println!("Native fe_native = {}", fe_native.to_hex());

    // let sponge_state = native.state.clone();
    // println!("Arkworks sponge state after permute = {:?}", sponge_state);

    // 你自己的模拟函数之后
    println!("Manual simulate state = {:?}", test_state);

    let mut st1 = native.state.clone();      // Arkworks 真正的内部状态
    let mut st2 = vec![ArkFq::zero(), ArkFq::from(42u8), ArkFq::zero()];
    poseidon_permute_simulate_native_fr(&mut st2, &config);
    assert_eq!(st1, st2);  // 应该通过
    println!("st1 = {:?}", st1);
    println!("st2 = {:?}", st2);

    let sponge_state: Vec<ArkFq> = native.state.clone();
    print_poseidon_state_hex("Arkworks sponge state after permute", &sponge_state);
    // print_poseidon_state_hex("Manual simulate state", &test_state);

    // 5. Constrain output equals native
    let out_var = state[config.capacity].clone();
    let (com_no, var_no) = prover.commit(fe_native.clone(), FieldElement::zero());
    // prover.constrain(out_var.into() - var_no.into());
    prover.constrain(out_var - var_no);

    // println!("Prover final output var_no = {:?}", var_no);
    // println!("Prover final output var = {:?}", state[config.capacity]);

    

    // 6. Prove + Verify
    let proof = prover.prove(&G, &H).unwrap();

    println!("Proving done!");

    // let mut v_transcript = Transcript::new(b"Poseidon");
    // let mut verifier = Verifier::new(&mut v_transcript);
    // // 重新提交
    // // let var_x0 = verifier.commit(com_x0);
    // // let var_x1 = verifier.commit(com_x1);
    // // let var_c  = verifier.commit(com_c);
    // // let mut vstate: Vec<LinearCombination> = vec![var_x0.into(), var_x1.into(), var_c.into()];
    // // 重新提交，保持顺序一致
    // let var_c  = verifier.commit(com_c);   // capacity
    // let var_x0 = verifier.commit(com_x0);  // 第 1 个输入
    // let var_x1 = verifier.commit(com_x1);  // 第 2 个输入

    // // 正确的初始 state
    // let mut vstate: Vec<LinearCombination> =
    //     vec![var_c.into(), var_x0.into(), var_x1.into()];
    // let half_full = config.full_rounds / 2;
    // let total_rounds = config.full_rounds + config.partial_rounds;

    // poseidon_permute_r1cs(&mut verifier, &mut vstate, &config, &ark_fe, &mds_fe);

    // // for round_idx in 0..total_rounds {
    // //     let round_constants_fe = &ark_fe[round_idx];

    // //     // full‑round / partial‑round 判断
    // //     let is_full_round =
    // //         round_idx < half_full ||
    // //         round_idx >= half_full + config.partial_rounds;

    // //     // ---------- S‑box ----------
    // //     let mut after_sbox = Vec::with_capacity(width);
    // //     for i in 0..width {
    // //         let mut lc = LinearCombination::default();
    // //         lc += round_constants_fe[i].clone() * Variable::One();
    // //         lc += vstate[i].clone();
    // //         let (_, _, lc_var) = verifier.multiply(lc.into(), Variable::One().into());

    // //         if is_full_round || i == 0 {
    // //             let mut pow_var = lc_var;
    // //             for _ in 0..(config.alpha - 1) {
    // //                 let (_, _, next) = verifier.multiply(pow_var.into(), lc_var.into());
    // //                 pow_var = next;
    // //             }
    // //             after_sbox.push(pow_var);
    // //         } else {
    // //             after_sbox.push(lc_var);
    // //         }
    // //     }

    // //     // ---------- MDS ----------
    // //     let mut next_state = Vec::with_capacity(width);
    // //     for j in 0..width {
    // //         let mut mds_lc = LinearCombination::default();
    // //         for k in 0..width {
    // //             mds_lc += mds_fe[j][k].clone() * after_sbox[k];
    // //         }
    // //         let (_, _, mds_var) = verifier.multiply(mds_lc.into(), Variable::One().into());
    // //         next_state.push(mds_var.into());
    // //     }
    // //     vstate = next_state;
    // // }
    // println!("Verifier state[0] = {:?}", vstate[config.capacity]);
    // let var_no = verifier.commit(com_no);
    // verifier.constrain(vstate[config.capacity].clone() - var_no);
    // // assert!(verifier.verify(&proof, &g, &h, &G, &H).is_ok());
    // match verifier.verify(&proof, &g, &h, &G, &H) {
    //     Ok(_) => println!("Verification passed"),
    //     Err(e) => println!("Verification failed: {:?}", e),
    // }
}

// #[test]
// fn test_2_factors_r1cs() {
//     // Prove knowledge of `p` and `q` such that given an `r`, `p * q = r`
//     let G: G1Vector = get_generators("G", 8).into();
//     let H: G1Vector = get_generators("H", 8).into();
//     // let g = G1::from_msg_hash("g".as_bytes());
//     // let h = G1::from_msg_hash("h".as_bytes());

//     let uncompressed_hex_g = "0417f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1";  // 用 Python 打印出来的 hex
//     let bytes_g = hex::decode(uncompressed_hex_g).unwrap();
//     let g = G1::from_bytes(&bytes_g).unwrap();

//     let uncompressed_hex_h = "041928f3beb93519eecf0145da903b40a4c97dca00b21f12ac0df3be9116ef2ef27b2ae6bcd4c5bc2d54ef5a70627efcb7108dadbaa4b636445639d5ae3089b3c43a8a1d47818edd1839d7383959a41c10fdc66849cfa1b08c5a11ec7e28981a1c";  // 用 Python 打印出来的 hex
//     let bytes_h = hex::decode(uncompressed_hex_h).unwrap();
//     let h = G1::from_bytes(&bytes_h).unwrap();

//     println!("g = {:?}", g);
//     println!("h = {:?}", h);

//     // println!("G vector:");
//     // for (i, g_i) in G.iter().enumerate() {
//     //     println!("G[{}] = {:?}", i, g_i);
//     // }

//     let mut factors = vec![
//         (
//             FieldElement::from_hex("1ab3ce638d5bdd7c3ae1c6a18fea44276b91d6ef3ad263a4d3a6d0147744453c".to_string()).unwrap(),
//             FieldElement::from_hex("bc3e8cba8c1f37460d429fe302816f7821a18b54d625bb5814239ba62129cc7".to_string()).unwrap(),
//             FieldElement::from_hex("2fc7b463304123935960a640d4a08f27a800debc80680450cface8fdd354844b".to_string()).unwrap(),
//         ),
//         (
//             FieldElement::from(7u32),
//             FieldElement::from(5u32),
//             FieldElement::from(35u32),
//         ),
//     ];

//     let (proof, mut commitments) = {
//         let mut comms = vec![];
//         let mut prover_transcript = Transcript::new(b"Factors");
//         let mut prover = Prover::new(&g, &h, &mut prover_transcript);

//         for (p, q, r) in &factors {
//             // let (com_p, var_p) = prover.commit(p.clone(), FieldElement::random());
//             // let (com_q, var_q) = prover.commit(q.clone(), FieldElement::random());
//             let (com_p, var_p) = prover.commit(p.clone(), p.clone());
//             let (com_q, var_q) = prover.commit(q.clone(), q.clone());
//             let (_, _, o) = prover.multiply(var_p.into(), var_q.into());
//             // let lc: LinearCombination = vec![(Variable::One(), r.clone())].iter().collect();
//             // prover.constrain(o - lc);
//             // let (com_r, var_r) = prover.commit(r.clone(), FieldElement::random());
//             let (com_r, var_r) = prover.commit(r.clone(), r.clone());
//             prover.constrain(o - var_r);
//             // prover.constrain(o.into() - lc);
//             comms.push(com_p);
//             comms.push(com_q);
//             comms.push(com_r);
//         }

//         let proof = prover.prove(&G, &H).unwrap();

//         (proof, comms)
//     };

//     println!("Proving done");

//     let mut verifier_transcript = Transcript::new(b"Factors");
//     let mut verifier = Verifier::new(&mut verifier_transcript);
//     for _ in factors.drain(0..) {
//     // for (_, _, r) in factors.drain(0..) {
//         let var_p = verifier.commit(commitments.remove(0));
//         let var_q = verifier.commit(commitments.remove(0));
//         let (_, _, o) = verifier.multiply(var_p.into(), var_q.into());
//         // let lc: LinearCombination = vec![(Variable::One(), r)].iter().collect();
//         // verifier.constrain(o - lc);
//         let var_r = verifier.commit(commitments.remove(0));
//         verifier.constrain(o - var_r);
//     }

//     println!("Starting verification...");
//     assert!(verifier.verify(&proof, &g, &h, &G, &H).is_ok());
//     println!("Verification passed.");
// }

// #[test]
// fn test_factor_r1cs() {
//     // Prove knowledge of `p` and `q` such that given an `r`, `p * q = r`
//     let G: G1Vector = get_generators("G", 8).into();
//     let H: G1Vector = get_generators("H", 8).into();
//     let g = G1::from_msg_hash("g".as_bytes());
//     let h = G1::from_msg_hash("h".as_bytes());

//     let mut factors = vec![
//         (
//             FieldElement::from(2u32),
//             FieldElement::from(4u32),
//             FieldElement::from(6u32),
//             FieldElement::from(48u32),
//         ),
//         (
//             FieldElement::from(7u32),
//             FieldElement::from(5u32),
//             FieldElement::from(35u32),
//             FieldElement::from(1225u32),
//         ),
//     ];

//     let (proof, mut commitments) = {
//         let mut comms = vec![];
//         let mut prover_transcript = Transcript::new(b"Factors");
//         let mut prover = Prover::new(&g, &h, &mut prover_transcript);

//         for (p, q, r, s) in &factors {
//             let (com_p, var_p) = prover.commit(p.clone(), FieldElement::random());
//             let (com_q, var_q) = prover.commit(q.clone(), FieldElement::random());
//             let (com_r, var_r) = prover.commit(r.clone(), FieldElement::random());
//             let (_, _, o1) = prover.multiply(var_p.into(), var_q.into());
//             let (_, _, o2) = prover.multiply(o1.into(), var_r.into());
//             let lc: LinearCombination = vec![(Variable::One(), s.clone())].iter().collect();
//             prover.constrain(o2 - lc);
//             comms.push(com_p);
//             comms.push(com_q);
//             comms.push(com_r);
//         }

//         let proof = prover.prove(&G, &H).unwrap();

//         (proof, comms)
//     };

//     println!("Proving done");

//     let mut verifier_transcript = Transcript::new(b"Factors");
//     let mut verifier = Verifier::new(&mut verifier_transcript);
//     for (_, _, _, s) in factors.drain(0..) {
//         let var_p = verifier.commit(commitments.remove(0));
//         let var_q = verifier.commit(commitments.remove(0));
//         let var_r = verifier.commit(commitments.remove(0));
//         let (_, _, o1) = verifier.multiply(var_p.into(), var_q.into());
//         let (_, _, o2) = verifier.multiply(o1.into(), var_r.into());
//         let lc: LinearCombination = vec![(Variable::One(), s)].iter().collect();
//         verifier.constrain(o2 - lc);
//     }

//     assert!(verifier.verify(&proof, &g, &h, &G, &H).is_ok());
// }
