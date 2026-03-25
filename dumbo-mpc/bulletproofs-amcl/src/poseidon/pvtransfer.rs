use crate::transcript::TranscriptProtocol;
use std::ops::Mul;
use amcl_wrapper::field_elem::FieldElement;
use amcl_wrapper::group_elem::{GroupElement};
use merlin::Transcript;

use crate::poseidon::{PoseidonSponge, DuplexSpongeMode, PoseidonConfig, find_poseidon_ark_and_mds};
use crate::poseidon::{poseidon_permute_prover, poseidon_permute_verifier};
use crate::r1cs::{ConstraintSystem, LinearCombination, Prover, Variable, Verifier};
use crate::r1cs::proof::R1CSProof;
use crate::utils::get_generators;

use amcl_wrapper::group_elem_g1::{G1Vector, G1};
use amcl_wrapper::group_elem::GroupElementVector; // 确保导入 trait

use serde::{Serialize, Deserialize};


/* ---------------- 结构体：把先前 HybridProof + Poseidon-R1CS 拼到一起 ---------------- */
macro_rules! static_labels_100 {
    () => {
        [
            b"T3a", b"T3b", b"T3c", b"T3d", b"T3e", b"T3f", b"T3g", b"T3h", b"T3i", b"T3j",
            b"T3k", b"T3l", b"T3m", b"T3n", b"T3o", b"T3p", b"T3q", b"T3r", b"T3s", b"T3t",
            b"T3u", b"T3v", b"T3w", b"T3x", b"T3y", b"T3z", b"T3A", b"T3B", b"T3C", b"T3D",
            b"T3E", b"T3F", b"T3G", b"T3H", b"T3I", b"T3J", b"T3K", b"T3L", b"T3M", b"T3N",
            b"T3O", b"T3P", b"T3Q", b"T3R", b"T3S", b"T3T", b"T3U", b"T3V", b"T3W", b"T3X",
            b"T3Y", b"T3Z", b"T30", b"T31", b"T32", b"T33", b"T34", b"T35", b"T36", b"T37",
            b"T38", b"T39", b"T40", b"T41", b"T42", b"T43", b"T44", b"T45", b"T46", b"T47",
            b"T48", b"T49", b"T50", b"T51", b"T52", b"T53", b"T54", b"T55", b"T56", b"T57",
            b"T58", b"T59", b"T60", b"T61", b"T62", b"T63", b"T64", b"T65", b"T66", b"T67",
            b"T68", b"T69", b"T70", b"T71", b"T72", b"T73", b"T74", b"T75", b"T76", b"T77"
        ]
    };
}
macro_rules! static_labels_10 {
    () => {
        [
            b"T3a", b"T3b", b"T3c", b"T3d", b"T3e", b"T3f", b"T3g", b"T3h", b"T3i", b"T3j"
        ]
    };
}
macro_rules! static_labels_2 {
    () => {
        [
            b"T3a", b"T3b"
        ]
    };
}


/// -------- batch size --------
const B: usize = 2;                    // number of (m,m′,W) tuples we handle
// 这里必须是static labels，不能动态生成
// const T3_LABELS: [&[u8]; 4] = [b"T3a", b"T3b", b"T3c", b"T3d"];   // static labels for Merlin
const T3_LABELS: [&'static [u8]; 2] = static_labels_2!();

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FullProof {
    /* --- Hybrid part (r & r′ unchanged) --- */
    pub T1: G1,
    pub T2: G1,
    pub T3: Vec<G1>,                       // ⬅️  now B commitments
    pub s_r: FieldElement,
    pub s_r_prime: FieldElement,
    pub s_m: Vec<FieldElement>,            // ⬅️  B responses
    pub s_m_prime: Vec<FieldElement>,      // ⬅️  B responses
    /* --- Poseidon‑R1CS part --- */
    pub r1cs_proof: R1CSProof,
    pub com_pk_rprime: G1,
    pub com_K:   G1,
    pub com_c:   Vec<G1>,                  // ⬅️  B commitments for c = m−K
    pub com_c_prime: Vec<G1>,              // ⬅️  B commitments for c′ = m′−K
    pub com_m:   Vec<G1>,                  // ⬅️  B commitments for m
    pub com_m_prime: Vec<G1>,             // ⬅️  B commitments for m′    
}

/* -------------------- Prover -------------------- */
#[allow(clippy::too_many_arguments)]
pub fn prove_full(
    g:&G1, h:&G1, pk:&G1,
    C1:&G1, C2:&G1, W:&[G1],          // ⬅️  B group elements
    r:&FieldElement, r_prime:&FieldElement,
    m:&[FieldElement], m_prime:&[FieldElement],
    poseidon_cfg:&PoseidonConfig,      // rate=2,cap=1
    ark_fe:&[Vec<FieldElement>], mds_fe:&[Vec<FieldElement>],
    G_vec:&[G1], H_vec:&[G1],
) -> FullProof {

    /* ------------------------------------------------------------------ */
    /*  0) 预计算具体的输入点  pk^{r'}  与   K = Poseidon(pk^{r'})         */
    /* ------------------------------------------------------------------ */

    // let t3_labels: Vec<Vec<u8>> = (0..B)
    //     .map(|i| format!("T3{}", (b'a' + i as u8) as char).into_bytes())
    //     .collect();

    // 0-1. 计算 pk^{r'} （群点）并压成字段元素
    let pk_rprime_pt = pk.mul(r_prime);
    let pk_rprime_bytes = pk_rprime_pt.to_bytes(true);                 // 48 B
    let pk_rprime_fe = FieldElement::from_bytes(&pk_rprime_bytes[1..]).unwrap();

    // 0-2. 原生 Poseidon 计算 K，用作电路输出的 *真实值*
    let K_native = {
        // use crate::poseidon::{PoseidonSponge, DuplexSpongeMode};
        let mut sponge = PoseidonSponge {
            parameters: poseidon_cfg.clone(),
            state: vec![FieldElement::zero(); 3],
            mode: DuplexSpongeMode::Absorbing { next_absorb_index: 0 },
        };
        sponge.absorb(0, &[pk_rprime_fe.clone()]);
        sponge.permute();
        let mut out = vec![FieldElement::zero(); 1];
        sponge.squeeze(0, &mut out);
        out[0].clone()
    };

    /* ------------------------------------------------------------------ */
    /*  1) Hybrid-Schnorr 片段（与之前相同）                              */
    /* ------------------------------------------------------------------ */
    let k_r       = FieldElement::random();
    let k_rprime  = FieldElement::random();

    let T1 = g .mul(&k_r);
    let T2 = pk.mul(&k_r) + &g.mul(&k_rprime);

    let mut T3              = Vec::with_capacity(B);
    let mut s_m             = Vec::with_capacity(B);
    let mut s_m_prime       = Vec::with_capacity(B);
    let mut com_m           = Vec::with_capacity(B);
    let mut var_m_vec       = Vec::with_capacity(B);
    let mut com_c           = Vec::with_capacity(B);
    let mut var_c_vec       = Vec::with_capacity(B);
    let mut com_c_prime     = Vec::with_capacity(B);
    let mut var_cprime_vec  = Vec::with_capacity(B);
    let mut com_m_prime     = Vec::with_capacity(B);
    let mut var_mprime_vec  = Vec::with_capacity(B);

    let mut tr = Transcript::new(b"HybridPoseidon");

    /* ① 先写入公开量 */
    tr.commit_point(b"g",  g);
    tr.commit_point(b"h",  h);
    tr.commit_point(b"pk", pk);
    tr.commit_point(b"C1", C1);
    tr.commit_point(b"C2", C2);
    tr.commit_point(b"W",  &W[0]);  // Commit at least one W for transcript consistency (optional)

    /* ② 生成并提交 B 个 Schnorr 承诺（T3_i） */
    for i in 0..B {
        // fresh randomness per tuple
        let k_m_i       = FieldElement::random();
        let k_mprime_i  = FieldElement::random();

        let T3_i = g.mul(&k_m_i) + &h.mul(&k_mprime_i);
        tr.commit_point(T3_LABELS[i], &T3_i);

        T3.push(T3_i);

        // will fill s_m *_i later after challenge
        s_m.push(k_m_i);        // temporarily store k_m_i
        s_m_prime.push(k_mprime_i);
    }

    /* ③ 再写入两个 Schnorr 承诺 */
    tr.commit_point(b"T1", &T1);
    tr.commit_point(b"T2", &T2);

    /* ④ 现在生成 challenge */
    let c = tr.challenge_scalar(b"c");

    /* ⑤ 提前生成四个 Schnorr 响应（必须在 Transcript交给Prover之前完成！） */
    let s_r        = &k_r       + &(c.clone() * r);
    let s_r_prime  = &k_rprime  + &(c.clone() * r_prime);
    for i in 0..B {
        let resp_m  = &s_m[i] + &(c.clone() * &m[i]);
        let resp_mp = &s_m_prime[i] + &(c.clone() * &m_prime[i]);
        s_m[i]       = resp_m;
        s_m_prime[i] = resp_mp;
    }

    let mut prov = Prover::new(g, h, &mut tr);

    /* 2-1. 提交外部变量 pk^{r'}、K 作为 “Committed 变量” */
    let (com_pk_rprime , var_pk_rprime) = prov.commit(pk_rprime_fe.clone(), FieldElement::random());
    let (com_K         , var_K        ) = prov.commit(K_native.clone()  , FieldElement::random());

    /* 2-2. 调 Poseidon gadget：state = [pk^{r'}, 0, 0] */
    let mut state_vars = vec![
        prov.allocate(Some(FieldElement::zero())).unwrap(),
        var_pk_rprime,
        prov.allocate(Some(FieldElement::zero())).unwrap(),
    ];

    // full_rounds 与 partial_rounds 直接从 cfg 里拿
    state_vars = poseidon_permute_prover(
        &mut prov,
        state_vars.clone(),           // 传入 state
        ark_fe,
        mds_fe,
        poseidon_cfg.full_rounds,
        poseidon_cfg.partial_rounds,
    );

    // 约束 state_vars[0] == K
    prov.constrain(state_vars[poseidon_cfg.capacity] - var_K);

    /* 2-3. 对每个 i 处理 m_i, c_i, c'_i 的 Pedersen 承诺以及约束 */
    for i in 0..B {
        // Pedersen commits: m_i
        let (cm,  var_m)  = prov.commit(m[i].clone(), FieldElement::random());
        com_m.push(cm);  var_m_vec.push(var_m);

        // c_i = m_i - K
        let c_i = &m[i] - &K_native;
        let (cc, var_c)  = prov.commit(c_i.clone(), FieldElement::random());
        com_c.push(cc);   var_c_vec.push(var_c);

        // c′_i = m′_i - K
        let cprime_i = &m_prime[i] - &K_native;
        let (ccp, var_cp) = prov.commit(cprime_i.clone(), FieldElement::random());
        com_c_prime.push(ccp);  var_cprime_vec.push(var_cp);

        // add constraints:   m_i - K - c_i == 0   and   m′_i - K - c′_i == 0
        prov.constrain(var_m  - var_K - var_c);
        let (cmprime, var_mprime) = prov.commit(m_prime[i].clone(), FieldElement::random());
        com_m_prime.push(cmprime);  var_mprime_vec.push(var_mprime);
        prov.constrain(var_mprime - var_K - var_cp);
    }

    /* 2-4. 任选生成几条 debug 输出（可删） */
    // println!("pk^r'   = {}", pk_rprime_fe.to_hex());
    // println!("PoseidonK = {}", K_native.to_hex());

    /* 2-5. 生成 R1CS 证明 */
    let (G_vec, H_vec): (Vec<G1>, Vec<G1>) = (G_vec.into(), H_vec.into());
    let r1cs_proof = prov.prove(&G_vec.into(), &H_vec.into()).unwrap();

    /* ------------------------------------------------------------------ */
    /*   3) 打包所有内容为 FullProof                                      */
    /* ------------------------------------------------------------------ */
    FullProof {
        T1, T2, T3,
        s_r,
        s_r_prime,
        s_m,
        s_m_prime,
        r1cs_proof,
        com_pk_rprime,
        com_K,
        com_c,
        com_c_prime,
        com_m,
        com_m_prime,
    }
}

/* ----------------------- Verifier（思路） -----------------------
   1. 复现 Hybrid Transcript → 计算同一个 c
   2. 检查三条 Schnorr 等式 (见上条回答)
   3. 用 r1cs::Verifier，把
        • com_pk_rprime 作为外部 committed 变量 0
        • poseidon_permute_r1cs 复算约束
        • 额外约束   var_m - var_K - var_c = 0   和 var_m - var_K - var_cprime + var_c - var_cprime = 0
      并验证 r1cs_proof
   -------------------------------------------------------------- */
/// 验证完整证明
#[allow(clippy::too_many_arguments)]
pub fn verify_full(
    g:&G1, h:&G1, pk:&G1,
    C1:&G1, C2:&G1, W:&[G1],      // ⬅️  B group elements
    proof:&FullProof,
    poseidon_cfg:&PoseidonConfig,
    ark_fe:&[Vec<FieldElement>], mds_fe:&[Vec<FieldElement>],
    G_vec:&[G1], H_vec:&[G1],
) -> bool {

    // let t3_labels: Vec<Vec<u8>> = (0..B)
    //     .map(|i| format!("T3{}", (b'a' + i as u8) as char).into_bytes())
    //     .collect();

    let mut tr = Transcript::new(b"HybridPoseidon");

    /* ① 公开量 */
    tr.commit_point(b"g",  g);
    tr.commit_point(b"h",  h);
    tr.commit_point(b"pk", pk);
    tr.commit_point(b"C1", C1);
    tr.commit_point(b"C2", C2);
    tr.commit_point(b"W",  &W[0]);  // Commit at least one W for transcript consistency (optional)

    /* ② Schnorr 承诺 T3_i */
    for i in 0..B {
        tr.commit_point(T3_LABELS[i], &proof.T3[i]);
    }

    /* ③ Schnorr 承诺 T1, T2 */
    tr.commit_point(b"T1", &proof.T1);
    tr.commit_point(b"T2", &proof.T2);

    /* ④ 同一位置取 challenge */
    let c = tr.challenge_scalar(b"c");

    /* ⑤ 再创建 R1CS Verifier —— 后续逻辑不变 */
    let mut verifier = Verifier::new(&mut tr);

    /* 2-1. 依 **与 Prover 相同的顺序** 提交外部承诺 */
    let var_pk_rprime = verifier.commit(proof.com_pk_rprime.clone());
    let var_K         = verifier.commit(proof.com_K.clone());

    let mut var_m_vec      = Vec::with_capacity(B);
    let mut var_c_vec      = Vec::with_capacity(B);
    let mut var_cprime_vec = Vec::with_capacity(B);
    let mut var_mprime_vec = Vec::with_capacity(B);
    
    for i in 0..B {
        var_m_vec.push( verifier.commit(proof.com_m[i].clone()) );
        var_c_vec.push( verifier.commit(proof.com_c[i].clone()) );
        var_cprime_vec.push( verifier.commit(proof.com_c_prime[i].clone()) );
        var_mprime_vec.push( verifier.commit(proof.com_m_prime[i].clone()) );
    }

    /* 2-2. 准备 Poseidon 状态变量并复现同样的约束 */
    let mut state_vars = vec![
        verifier.allocate(Some(FieldElement::zero())).unwrap(),
        var_pk_rprime,
        verifier.allocate(Some(FieldElement::zero())).unwrap(),
    ];

    state_vars = poseidon_permute_verifier(
        &mut verifier,
        state_vars.clone(),
        ark_fe,
        mds_fe,
        poseidon_cfg.full_rounds,
        poseidon_cfg.partial_rounds,
    );
    verifier.constrain(state_vars[poseidon_cfg.capacity] - var_K);          // K = state[0]

    /* 2-3. 约束   m − K − c = 0   和   m′ − K − c′ = 0 */
    for i in 0..B {
        verifier.constrain(var_m_vec[i] - var_K - var_c_vec[i]);
        verifier.constrain(var_mprime_vec[i] - var_K - var_cprime_vec[i]);
    }

    /* --------------------------------------------------------- */
    /* 3) 计算 Schnorr-style challenge c 并验证三条等式           */
    /*    ※ 必须在 verifier.build() 之前读取！                    */
    /* --------------------------------------------------------- */
    

    let ok1 = g .mul(&proof.s_r) ==
              &proof.T1 + &C1.mul(&c);
    let ok2 = pk.mul(&proof.s_r) + &g.mul(&proof.s_r_prime) ==
              &proof.T2 + &C2.mul(&c);
    let ok3 = (0..B).all(|i| {
        g.mul(&proof.s_m[i]) + &h.mul(&proof.s_m_prime[i]) ==
            &proof.T3[i] + &W[i].clone().mul(&c)
    });

    println!("[Verifier] ok1 (C1 = g^r): {}", ok1);
    println!("[Verifier] ok2 (C2 = pk^r + g^r'): {}", ok2);
    println!("[Verifier] ok3 (W  = g^m h^m'): {}", ok3);

    /* --------------------------------------------------------- */
    /* 4) 验证 R1CS 证明                                         */
    /* --------------------------------------------------------- */
    let r1cs_ok = verifier
        .verify(&proof.r1cs_proof, &g, &h, &G_vec.into(), &H_vec.into())
        .is_ok();
    
    println!("[Verifier] ok4 (Poseidon R1CS proof): {}", r1cs_ok);


    ok1 && ok2 && ok3 && r1cs_ok
}

/* ----------------------- 单元测试 ------------------------------- */
#[test]
fn full_hybrid_poseidon_ok() {
    /* —— 公共参数 —— */
    let g  = G1::from_msg_hash(b"g");
    let h  = G1::from_msg_hash(b"h");
    let sk = FieldElement::from(123u64);
    let pk = g.clone().mul(&sk);

    /* —— witness —— */
    let r  = FieldElement::from(77u64);
    let r_prime = FieldElement::from(314u64);

    let m_vals: Vec<FieldElement> = (0..B).map(|i| FieldElement::from(42u64 + i as u64)).collect();
    let mprime_vals: Vec<FieldElement> = (0..B).map(|i| FieldElement::from(2024u64 + i as u64)).collect();
    let W_vec: Vec<G1> = (0..B).map(|i| g.clone().mul(&m_vals[i]) + &h.clone().mul(&mprime_vals[i])).collect();

    /* —— statement C1, C2 —— */
    let C1 = g.clone().mul(&r);
    let C2 = pk.clone().mul(&r) + &g.clone().mul(&r_prime);

    /* Poseidon 参数（rate=2, capacity=1） */
    let (ark, mds) = find_poseidon_ark_and_mds(
        255, 2, 8, 57, 0);         // 示例：full=8,partial=57,alpha=5
    println!("hybrid ark[0] len: {}", ark[0].len());
    println!("hybrid mds len: {}", mds.len());
    println!("hybrid mds[0] len: {}", mds[0].len());
    let cfg = PoseidonConfig::new(
        8, 57, 5, mds.clone(), ark.clone(), 2, 1);

    /* —— Bulletproof generators —— */
    let gens = 8usize.next_power_of_two();       // 测试随便取 ≥ 8
    let G_vec = get_generators("G", 4096);
    let H_vec = get_generators("H", 4096);

    /* —— 生成证明 —— */
    let proof = prove_full(
        &g,&h,&pk,&C1,&C2,&W_vec,
        &r,&r_prime,
        &m_vals,&mprime_vals,
        &cfg,&ark,&mds,&G_vec,&H_vec);

    println!("Proving done");

    let mut total_bytes = 0;

    // G1 类型成员（压缩为 48 bytes）
    total_bytes += proof.T1.to_bytes(true).len();
    total_bytes += proof.T2.to_bytes(true).len();
    total_bytes += proof.T3.iter().map(|pt| pt.to_bytes(true).len()).sum::<usize>();
    total_bytes += proof.com_pk_rprime.to_bytes(true).len();
    total_bytes += proof.com_K.to_bytes(true).len();
    total_bytes += proof.com_c.iter().map(|pt| pt.to_bytes(true).len()).sum::<usize>();
    total_bytes += proof.com_c_prime.iter().map(|pt| pt.to_bytes(true).len()).sum::<usize>();
    total_bytes += proof.com_m.iter().map(|pt| pt.to_bytes(true).len()).sum::<usize>();
    total_bytes += proof.com_m_prime.iter().map(|pt| pt.to_bytes(true).len()).sum::<usize>();

    // FieldElement 类型成员（AMCL字段默认 48 bytes）
    total_bytes += proof.s_r.to_bytes().len();
    total_bytes += proof.s_r_prime.to_bytes().len();
    total_bytes += proof.s_m.iter().map(|f| f.to_bytes().len()).sum::<usize>();
    total_bytes += proof.s_m_prime.iter().map(|f| f.to_bytes().len()).sum::<usize>();

    // R1CSProof：目前你没法直接看大小，但你可以看一下内含的向量长度
    use std::mem::size_of_val;
    println!("R1CSProof type = {:?}", std::any::type_name::<R1CSProof>());
    println!("R1CSProof size (stack only): {} bytes", size_of_val(&proof.r1cs_proof));

    // 输出总长度
    println!("Approx proof byte size (excluding R1CS): {} bytes", total_bytes);
    
    /* —— Verify —— */
    assert!(
        verify_full(
            &g,&h,&pk,&C1,&C2,&W_vec,
            &proof,
            &cfg,&ark,&mds,&G_vec,&H_vec
        ),
        "verification failed"
    );
}