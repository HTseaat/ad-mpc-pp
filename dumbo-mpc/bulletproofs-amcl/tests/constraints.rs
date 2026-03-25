use bulletproofs_amcl::poseidon::{PoseidonConfig, find_poseidon_ark_and_mds};
use bulletproofs_amcl::r1cs::{ConstraintSystem, LinearCombination, Prover, Variable, Verifier};
use amcl_wrapper::field_elem::FieldElement;
use merlin::Transcript;
use hex;
use amcl_wrapper::group_elem::GroupElement;
use amcl_wrapper::group_elem_g1::{G1Vector, G1};
use amcl_wrapper::group_elem::GroupElementVector; // 确保导入 trait

fn poseidon_permute_prover(
    cs: &mut Prover,
    mut state: Vec<Variable>,
    ark: &[Vec<FieldElement>],
    mds: &[Vec<FieldElement>],
    full_rounds: usize,
    partial_rounds: usize,
) -> Vec<Variable> {
    let width = state.len();
    let half_full = full_rounds / 2;
    let total_rounds = full_rounds + partial_rounds;

    for r in 0..total_rounds {
        // Step 1: Add round constant
        let mut arked = vec![];
        for i in 0..width {
            let var_val = cs.evaluate_lc(&state[i].into()).unwrap();
            let c_val = ark[r][i].clone();
            let sum_val = &var_val + &c_val;
            let c = cs.allocate(Some(c_val)).unwrap();
            let sum = cs.allocate(Some(sum_val)).unwrap();
            cs.constrain(state[i] + c - sum);
            arked.push(sum);
        }

        // Step 2: Apply S-box
        let mut sboxed = vec![];
        for i in 0..width {
            let x = arked[i];
            if r < half_full || r >= half_full + partial_rounds {
                // full round: all elements x^5
                let (_, _, x2) = cs.multiply(x.into(), x.into());
                let (_, _, x4) = cs.multiply(x2.into(), x2.into());
                let (_, _, x5) = cs.multiply(x4.into(), x.into());
                sboxed.push(x5);
            } else if i == 0 {
                // partial round: only x_0 ^ 5
                let (_, _, x2) = cs.multiply(x.into(), x.into());
                let (_, _, x4) = cs.multiply(x2.into(), x2.into());
                let (_, _, x5) = cs.multiply(x4.into(), x.into());
                sboxed.push(x5);
            } else {
                // bypass other elements
                sboxed.push(x);
            }
        }

        // Step 3: Apply MDS
        let mut new_state = vec![];
        for i in 0..width {
            let mut lc = LinearCombination::default();
            let acc = sboxed
                .iter()
                .enumerate()
                .map(|(j, sbox_j)| {
                    let lc = LinearCombination::from(*sbox_j);
                    cs.evaluate_lc(&lc).unwrap() * &mds[i][j]
                })
                .fold(FieldElement::zero(), |a, b| a + b);
            for j in 0..width {
                lc += mds[i][j].clone() * sboxed[j];
            }
            let out = cs.allocate(Some(acc)).unwrap();
            cs.constrain(out - lc);
            new_state.push(out);
        }

        state = new_state;
    }

    state
}

fn poseidon_permute_verifier(
    cs: &mut Verifier,
    mut state: Vec<Variable>,
    ark: &[Vec<FieldElement>],
    mds: &[Vec<FieldElement>],
    full_rounds: usize,
    partial_rounds: usize,
) -> Vec<Variable> {
    println!("state len: {}", state.len());
    let width = state.len();
    let half_full = full_rounds / 2;
    let total_rounds = full_rounds + partial_rounds;


    for r in 0..total_rounds {
        // Step 1: Add round constants
        let mut arked = vec![];
        for i in 0..width {
            let c = cs.allocate(Some(ark[r][i].clone())).unwrap();
            let sum = cs.allocate(None).unwrap();
            cs.constrain(state[i] + c - sum);
            arked.push(sum);
        }

        // Step 2: Apply S-box
        let mut sboxed = vec![];
        for i in 0..width {
            let x = arked[i];
            if r < half_full || r >= half_full + partial_rounds {
                // full round
                let (_, _, x2) = cs.multiply(x.into(), x.into());
                let (_, _, x4) = cs.multiply(x2.into(), x2.into());
                let (_, _, x5) = cs.multiply(x4.into(), x.into());
                sboxed.push(x5);
            } else if i == 0 {
                // partial round
                let (_, _, x2) = cs.multiply(x.into(), x.into());
                let (_, _, x4) = cs.multiply(x2.into(), x2.into());
                let (_, _, x5) = cs.multiply(x4.into(), x.into());
                sboxed.push(x5);
            } else {
                sboxed.push(x);
            }
        }

        // Step 3: Apply MDS
        let mut new_state = vec![];
        for i in 0..width {
            let mut lc = LinearCombination::default();
            for j in 0..width {
                lc += mds[i][j].clone() * sboxed[j];
            }
            let out = cs.allocate(None).unwrap();
            cs.constrain(out - lc);
            new_state.push(out);
        }

        state = new_state;
    }

    state
}

// ================= helper: absorb ≤rate elements =================
fn absorb_chunk_prover(
    cs: &mut Prover,
    state: &mut Vec<Variable>,
    chunk: &[Variable],
    capacity: usize,
) {
    for (slot, &inp) in chunk.iter().enumerate() {
        let idx = capacity + slot;                 // rate 槽位置
        let sum_val = cs.evaluate_lc(&state[idx].into()).unwrap()
            + cs.evaluate_lc(&inp.into()).unwrap();
        let sum = cs.allocate(Some(sum_val)).unwrap();
        cs.constrain(state[idx] + inp - sum);      // sum = old + inp
        state[idx] = sum;                          // 更新 state
    }
}

fn absorb_chunk_verifier(
    cs: &mut Verifier,
    state: &mut Vec<Variable>,
    chunk: &[Variable],
    capacity: usize,
) {
    for (slot, &inp) in chunk.iter().enumerate() {
        let idx = capacity + slot;
        let sum = cs.allocate(None).unwrap();
        cs.constrain(state[idx] + inp - sum);
        state[idx] = sum;
    }
}

/// 用 Bulletproofs R1CS 构造一轮 Poseidon full-round：apply ark → S-box (x^5) → MDS
fn poseidon_full_round_prover(
    cs: &mut Prover,
    state: &[Variable],
    ark: &[FieldElement],
    mds: &[Vec<FieldElement>],
) -> Vec<Variable> {
    let mut arked = vec![];

    println!("mds len: {}", mds.len());

    // Step 1: Add round key
    for (i, &var) in state.iter().enumerate() {
        let c_val = ark[i].clone();
        let c = cs.allocate(Some(c_val.clone())).unwrap();
        let var_val = cs.evaluate_lc(&var.into()).unwrap();
        let sum_val = &var_val + &c_val;
        let sum = cs.allocate(Some(sum_val)).unwrap();
        // let c = cs.allocate(Some(ark[i].clone())).unwrap();      // 分配常量
        // let sum = cs.allocate(None).unwrap();            // 分配结果变量
        cs.constrain(var + c - sum);                     // 约束 sum = var + ark
        arked.push(sum);
        println!("i: {}", i);
    }

    println!("arked len: {}", arked.len());
    // Step 2: Apply S-box (x^5)
    let mut sboxed = vec![];
    for x in arked {
        let (_, _, x2) = cs.multiply(x.into(), x.into());
        let (_, _, x4) = cs.multiply(x2.into(), x2.into());
        let (_, _, x5) = cs.multiply(x4.into(), x.into());
        sboxed.push(x5);
    }
    println!("sboxed len: {}", sboxed.len());

    // Step 3: Apply MDS
    let mut new_state = vec![];
    for i in 0..mds.len() {
        let mut lc = LinearCombination::default();
        let mut acc = FieldElement::zero();

        for j in 0..mds[i].len() {
            lc += mds[i][j].clone() * sboxed[j];
            let sboxed_val = cs.evaluate_lc(&sboxed[j].into()).unwrap();
            acc += &mds[i][j] * &sboxed_val;
        }

        let out = cs.allocate(Some(acc)).unwrap();  // ✅ 提供真实值
        cs.constrain(out - lc);
        new_state.push(out);
    }

    new_state
}

fn poseidon_full_round_verifier(
    cs: &mut Verifier,
    state: &[Variable],
    ark: &[FieldElement],
    mds: &[Vec<FieldElement>],
) -> Vec<Variable> {
    let mut arked = vec![];

    // Step 1: Add round key
    for (i, &var) in state.iter().enumerate() {
        let c_val = ark[i].clone();
        let c = cs.allocate(Some(c_val.clone())).unwrap();
        let sum = cs.allocate(None).unwrap();
        cs.constrain(var + c - sum);
        arked.push(sum);
    }

    // Step 2: Apply S-box (x^5)
    let mut sboxed = vec![];
    for x in arked {
        let (_, _, x2) = cs.multiply(x.into(), x.into());
        let (_, _, x4) = cs.multiply(x2.into(), x2.into());
        let (_, _, x5) = cs.multiply(x4.into(), x.into());
        sboxed.push(x5);
    }

    // Step 3: Apply MDS
    let mut new_state = vec![];
    for i in 0..mds.len() {
        let mut lc = LinearCombination::default();
        for j in 0..mds[i].len() {
            lc += mds[i][j].clone() * sboxed[j];
        }

        let out = cs.allocate(None).unwrap(); // verifier 不知道实际值
        cs.constrain(out - lc);
        new_state.push(out);
    }

    new_state
}

#[test]
fn test_poseidon_constraints_basic() {
    let full_rounds = 8;
    let partial_rounds = 31;
    let alpha = 5;
    let rate = 2;
    let capacity = 1;
    let width = rate + capacity;

    // 生成 ARK 和 MDS
    let (ark, mds) = find_poseidon_ark_and_mds(255, rate, full_rounds as u64, partial_rounds as u64, 0);

    let _config = PoseidonConfig::new(full_rounds, partial_rounds, alpha, mds.clone(), ark.clone(), rate, capacity);

    

    let mut transcript = Transcript::new(b"PoseidonTest");
    let uncompressed_hex_g = "0417f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1";
    let bytes_g = hex::decode(uncompressed_hex_g).unwrap();
    let g = G1::from_bytes(&bytes_g).unwrap();

    let uncompressed_hex_h = "041928f3beb93519eecf0145da903b40a4c97dca00b21f12ac0df3be9116ef2ef27b2ae6bcd4c5bc2d54ef5a70627efcb7108dadbaa4b636445639d5ae3089b3c43a8a1d47818edd1839d7383959a41c10fdc66849cfa1b08c5a11ec7e28981a1c";
    let bytes_h = hex::decode(uncompressed_hex_h).unwrap();
    let h = G1::from_bytes(&bytes_h).unwrap();
    let mut cs = Prover::new(&g, &h, &mut transcript);

    let G_vec = G1Vector::from(vec![g.clone(); 4096]);
    let H_vec = G1Vector::from(vec![h.clone(); 4096]);

    // // 输入状态变量（3个）
    // // 第一个变量对应capacity，在我们的哈希中capacity默认为0，后两个才是要哈希的值
    // let inputs = vec![
    //     FieldElement::from(0u64),
    //     FieldElement::from(42u64),
    //     FieldElement::from(2024u64),
    // ];

    // println!("ark len: {}", ark.len());
    // println!("mds[0] len: {}", mds[0].len());


    // let mut commitments = vec![];  // 用于保存 G1 承诺值
    // let vars: Vec<Variable> = inputs
    //     .iter()
    //     .map(|x| {
    //         let (com, var) = cs.commit(x.clone(), FieldElement::random());
    //         commitments.push(com);
    //         var
    //     })
    //     .collect();

    // // 只跑第一轮 full-round 做约束验证
    // // let out = poseidon_full_round_prover(&mut cs, &vars, &ark[0], &mds);

    // let out = poseidon_permute_prover(&mut cs, vars, &ark, &mds, full_rounds, partial_rounds);
    // assert_eq!(out.len(), width);

    // // after poseidon_permute_prover returns `state_vars`
    // let digest_val = cs.evaluate_lc(&out[capacity].into()).unwrap();
    // let (com_digest, var_digest) = cs.commit(digest_val.clone(), FieldElement::random());
    // commitments.push(com_digest);         // 让 verifier 也能拿到
    // // 约束声明：digest_var == state[capacity]
    // cs.constrain(var_digest - out[capacity]);

    // let proof = cs.prove(&G_vec, &H_vec).unwrap();
    // println!("Proving done");


    // ---------- 1) 输入承诺 ----------
    let mut commitments = vec![];
    let input_fes = vec![
        FieldElement::from(0u64),    // capacity
        FieldElement::from(42u64),
        FieldElement::from(2024u64),
        FieldElement::from(314u64),  // 再加一个额外 input 示范
    ];

    let committed_vars: Vec<Variable> = input_fes
        .iter()
        .map(|fe| {
            let (com, var) = cs.commit(fe.clone(), FieldElement::random());
            commitments.push(com);
            var
        })
        .collect();

    // ---------- 2) 初始化 state = [capacity, 0, 0] ----------
    let mut state_vars = vec![committed_vars[0]];               // capacity
    for _ in 0..rate {
        state_vars.push(cs.allocate(Some(FieldElement::zero())).unwrap());
    }

    // ---------- 3) Sponge: absorb-permute 循环 ----------
    let data_vars = &committed_vars[1..];                       // 真正输入
    let mut cur_state = state_vars;
    for chunk in data_vars.chunks(rate) {                       // rate=2
        absorb_chunk_prover(&mut cs, &mut cur_state, chunk, capacity);
        cur_state = poseidon_permute_prover(
            &mut cs,
            cur_state,
            &ark,
            &mds,
            full_rounds,
            partial_rounds,
        );
    }

    // ---------- 4) 生成 digest 约束 ----------
    let digest_val = cs.evaluate_lc(&cur_state[capacity].into()).unwrap();
    let (com_digest, var_digest) = cs.commit(digest_val, FieldElement::random());
    commitments.push(com_digest);               // 传给 verifier
    cs.constrain(var_digest - cur_state[capacity]);

    // ---------- 5) 生成证明 ----------
    let proof = cs.prove(&G_vec, &H_vec).unwrap();
    println!("Proving done");

    println!("commitments len: {}", commitments.len());

    let mut transcript = Transcript::new(b"PoseidonTest");
    let mut verifier = Verifier::new(&mut transcript);

    // ---------- 1) 取出承诺 ----------
    let all_vars: Vec<Variable> = commitments
        .into_iter()
        .map(|c| verifier.commit(c))
        .collect();

    // ---------- 2) rebuild state ----------
    let mut v_state = vec![all_vars[0]];                       // capacity
    for _ in 0..rate {
        v_state.push(verifier.allocate(Some(FieldElement::zero())).unwrap());
    }
    let v_inputs = &all_vars[1..all_vars.len() - 1];           // 数据
    let v_digest = *all_vars.last().unwrap();

    // ---------- 3) Sponge 验证循环 ----------
    let mut cur_state_v = v_state;
    for chunk in v_inputs.chunks(rate) {
        absorb_chunk_verifier(&mut verifier, &mut cur_state_v, chunk, capacity);
        cur_state_v = poseidon_permute_verifier(
            &mut verifier,
            cur_state_v,
            &ark,
            &mds,
            full_rounds,
            partial_rounds,
        );
    }

    // ---------- 4) 绑定 digest ----------
    verifier.constrain(v_digest - cur_state_v[capacity]);

    println!("Starting verification...");
    assert!(verifier.verify(&proof, &g, &h, &G_vec, &H_vec).is_ok());
    println!("Verification passed.");

    // let vars: Vec<Variable> = commitments
    //     .iter()
    //     .map(|com| verifier.commit(com.clone()))
    //     .collect();

    
    // // 2. 前 `width` 个是 Poseidon 初始 state（capacity + rate），最后 1 个是 digest
    // let state_vars = vars[..width].to_vec();
    // let var_digest = vars[width];

    // // 3. 运行置换电路并添加 digest 约束
    // let out_var = poseidon_permute_verifier(&mut verifier, state_vars, &ark, &mds, full_rounds, partial_rounds);

    // // vars 最后一个是 commit 的哈希值，即 digest
    // // let var_digest = vars[width];  // width = rate + capacity = 3
    // verifier.constrain(var_digest - out_var[capacity]);

    // println!("Starting verification...");
    // assert!(verifier.verify(&proof, &g, &h, &G_vec, &H_vec).is_ok());
    // println!("Verification passed.");   

    // // assert_eq!(out.len(), width);

    // // === Proof generation and verification ===
    // // Generate proof
    // let proof = cs.prove(&G1Vector::from(vec![g.clone(); 64]), &G1Vector::from(vec![h.clone(); 64])).unwrap();

    // let mut transcript = Transcript::new(b"PoseidonTest");
    // let mut verifier = Verifier::new(&mut transcript);

    // let vars: Vec<Variable> = commitments
    //     .iter()
    //     .map(|com| verifier.commit(com.clone()))
    //     .collect();

    // let out_verifier = poseidon_full_round_verifier(&mut verifier, &vars, &ark[0], &mds);
    // assert_eq!(out_verifier.len(), width);

    // // assert!(verifier.verify(&proof, &g, &h, &G1Vector::from(vec![g; 64]), &G1Vector::from(vec![h; 64])).is_ok());
    // assert!(verifier.verify(&proof, &g, &h, &G_vec, &H_vec).is_ok());
}

// ================================================================
//  新测试：哈希输入为 G1 Group Element
// ================================================================
#[test]
fn test_poseidon_constraints_group_element() {
    use bulletproofs_amcl::poseidon::{DuplexSpongeMode, PoseidonSponge};

    // ---------- 参数 ----------
    let full_rounds = 8;
    let partial_rounds = 31;
    let alpha = 5;
    let rate = 2;
    let capacity = 1;
    let width = rate + capacity;

    let (ark, mds) =
        find_poseidon_ark_and_mds(255, rate, full_rounds as u64, partial_rounds as u64, 0);
    let cfg = PoseidonConfig::new(
        full_rounds,
        partial_rounds,
        alpha,
        mds.clone(),
        ark.clone(),
        rate,
        capacity,
    );

    // ---------- 准备 G1 点并压缩 ----------
    let uncompressed_hex_g = "0417f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1";
    let bytes_g = hex::decode(uncompressed_hex_g).unwrap();
    let g = G1::from_bytes(&bytes_g).unwrap();
    // let ge_bytes = g.to_bytes();                    // 48-byte compressed form
    let ge_bytes = g.to_bytes(true);  // ✅ 推荐：压缩格式用于哈希
    // assert_eq!(ge_bytes.len(), 48);          // ✅ 断言确保是 48 字节
    let ge_fe = FieldElement::from_bytes(&ge_bytes[1..]).unwrap();

    // ---------- Native 期望 digest ----------
    let mut nat = PoseidonSponge {
        parameters: cfg.clone(),
        state: vec![FieldElement::zero(); width],
        mode: DuplexSpongeMode::Absorbing { next_absorb_index: 0 },
    };
    nat.absorb(0, &[ge_fe.clone()]);
    nat.permute();
    let mut out = vec![FieldElement::zero()];
    nat.squeeze(0, &mut out);
    let expected_digest = out[0].clone();

    // ---------- Pedersen 生成元 ----------
    let uncompressed_hex_h = "041928f3beb93519eecf0145da903b40a4c97dca00b21f12ac0df3be9116ef2ef27b2ae6bcd4c5bc2d54ef5a70627efcb7108dadbaa4b636445639d5ae3089b3c43a8a1d47818edd1839d7383959a41c10fdc66849cfa1b08c5a11ec7e28981a1c";
    let bytes_h = hex::decode(uncompressed_hex_h).unwrap();
    let h = G1::from_bytes(&bytes_h).unwrap();
    let G_vec = G1Vector::from(vec![g.clone(); 4096]);
    let H_vec = G1Vector::from(vec![h.clone(); 4096]);

    // ======================  Prover  ======================
    let mut prover_ts = Transcript::new(b"PoseidonGE");
    let mut cs = Prover::new(&g, &h, &mut prover_ts);

    // 1) 输入承诺：capacity=0, ge_fe
    let mut comms = vec![];
    let inputs = vec![FieldElement::zero(), ge_fe.clone()];
    let vars: Vec<Variable> = inputs
        .iter()
        .map(|fe| {
            let (c, v) = cs.commit(fe.clone(), FieldElement::random());
            comms.push(c);
            v
        })
        .collect();

    // 2) 初始 state = [cap, 0, 0]
    let mut state = vec![vars[0]];
    for _ in 0..rate {
        state.push(cs.allocate(Some(FieldElement::zero())).unwrap());
    }

    // 3) 吸收 + 置换
    absorb_chunk_prover(&mut cs, &mut state, &vars[1..], capacity);
    state = poseidon_permute_prover(
        &mut cs, state, &ark, &mds, full_rounds, partial_rounds,
    );

    // 4) digest
    let dig_val = cs.evaluate_lc(&state[capacity].into()).unwrap();
    assert_eq!(dig_val, expected_digest);          // 与 native 匹配
    let (c_dig, v_dig) = cs.commit(dig_val, FieldElement::random());
    comms.push(c_dig);
    cs.constrain(v_dig - state[capacity]);

    // 5) 生成证明
    let proof = cs.prove(&G_vec, &H_vec).unwrap();

    // ======================  Verifier  ======================
    let mut ver_ts = Transcript::new(b"PoseidonGE");
    let mut verifier = Verifier::new(&mut ver_ts);

    let vars_all: Vec<Variable> = comms.into_iter().map(|c| verifier.commit(c)).collect();
    let mut v_state = vec![vars_all[0]];
    for _ in 0..rate {
        v_state.push(verifier.allocate(Some(FieldElement::zero())).unwrap());
    }
    let v_input = &vars_all[1..vars_all.len() - 1];
    let v_digest = *vars_all.last().unwrap();

    absorb_chunk_verifier(&mut verifier, &mut v_state, v_input, capacity);
    v_state = poseidon_permute_verifier(
        &mut verifier, v_state, &ark, &mds, full_rounds, partial_rounds,
    );
    verifier.constrain(v_digest - v_state[capacity]);

    assert!(verifier.verify(&proof, &g, &h, &G_vec, &H_vec).is_ok());
}