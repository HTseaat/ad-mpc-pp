//! witness = { r, r', m, m' }
//! statement = (g,h,pk,C1,C2,W)
//!
//! 三条需证明的等式：
//!   C1 = g^r
//!   C2 = pk^r + h^{r'}
//!   W  = g^m  h^{m'}

use bulletproofs_amcl::transcript::TranscriptProtocol;
use std::ops::Mul;
use amcl_wrapper::field_elem::FieldElement;
use amcl_wrapper::group_elem::{GroupElement};
use merlin::Transcript;

use bulletproofs_amcl::poseidon::{PoseidonSponge, DuplexSpongeMode, PoseidonConfig, find_poseidon_ark_and_mds};
use bulletproofs_amcl::poseidon::{poseidon_permute_prover, poseidon_permute_verifier};
use bulletproofs_amcl::r1cs::{ConstraintSystem, LinearCombination, Prover, Variable, Verifier};
use bulletproofs_amcl::r1cs::proof::R1CSProof;
use bulletproofs_amcl::utils::get_generators;

use amcl_wrapper::group_elem_g1::{G1Vector, G1};
use amcl_wrapper::group_elem::GroupElementVector; // 确保导入 trait

/* ------------------------- 证明结构体 ------------------------- */
#[derive(Clone, Debug)]
struct HybridProof {
    T1: G1, T2: G1, T3: G1,
    s_r: FieldElement,          // r
    s_r_prime: FieldElement,    // r'
    s_m: FieldElement,          // m
    s_m_prime: FieldElement,    // m'
}

/* ---------------------------  Prover  ------------------------- */
#[allow(clippy::too_many_arguments)]
fn prove(
    g: &G1, h: &G1, pk: &G1,
    C1:&G1, C2:&G1, W:&G1,
    r:&FieldElement, r_prime:&FieldElement,
    m:&FieldElement, m_prime:&FieldElement,
) -> HybridProof {

    /* 随机掩码 */
    let k_r       = FieldElement::random();
    let k_r_prime = FieldElement::random();
    let k_m       = FieldElement::random();
    let k_m_prime = FieldElement::random();

    /* 承诺 */
    let T1 = g .mul(&k_r);                           // g^{k_r}
    let T2 = pk.mul(&k_r) + &g.mul(&k_r_prime);      // pk^{k_r} + h^{k_r'}
    let T3 = g .mul(&k_m) + &h.mul(&k_m_prime);      // g^{k_m}  + h^{k_m'}

    /* Fiat–Shamir */
    let mut tr = Transcript::new(b"Hybrid-PoK");
    tr.commit_point(b"g",g); tr.commit_point(b"h",h); tr.commit_point(b"pk",pk);
    tr.commit_point(b"C1",C1); tr.commit_point(b"C2",C2); tr.commit_point(b"W",W);
    tr.commit_point(b"T1",&T1); tr.commit_point(b"T2",&T2); tr.commit_point(b"T3",&T3);
    let c = tr.challenge_scalar(b"c");

    /* 响应 */
    let s_r        = &k_r       + &(c.clone()*r);
    let s_r_prime  = &k_r_prime + &(c.clone()*r_prime);
    let s_m        = &k_m       + &(c.clone()*m);
    let s_m_prime  = &k_m_prime + &(c       *m_prime);

    HybridProof{T1,T2,T3,s_r,s_r_prime,s_m,s_m_prime}
}

/* --------------------------- Verifier ------------------------- */
fn verify(
    g: &G1, h:&G1, pk:&G1,
    C1:&G1, C2:&G1, W:&G1,
    pr:&HybridProof,
) -> bool {

    /* 重建挑战 */
    let mut tr = Transcript::new(b"Hybrid-PoK");
    tr.commit_point(b"g",g); tr.commit_point(b"h",h); tr.commit_point(b"pk",pk);
    tr.commit_point(b"C1",C1); tr.commit_point(b"C2",C2); tr.commit_point(b"W",W);
    tr.commit_point(b"T1",&pr.T1); tr.commit_point(b"T2",&pr.T2); tr.commit_point(b"T3",&pr.T3);
    let c = tr.challenge_scalar(b"c");

    /* 三条等式 */
    let ok1 = g .mul(&pr.s_r) == &pr.T1 + &C1.mul(&c);
    let ok2 = pk.mul(&pr.s_r) + &g.mul(&pr.s_r_prime) == &pr.T2 + &C2.mul(&c);
    let ok3 = g .mul(&pr.s_m) + &h.mul(&pr.s_m_prime) == &pr.T3 + &W.mul(&c);

    ok1 && ok2 && ok3
}

/* --------------------------- 单元测试 ------------------------- */
#[test]
fn hybrid_proof_works() {
    /* 公开参数 */
    let g  = G1::from_msg_hash(b"g");
    let h  = G1::from_msg_hash(b"h");
    let sk = FieldElement::from(123u64);
    let pk = g.clone().mul(&sk);

    /* witness */
    let r  = FieldElement::from(77u64);
    let r_prime = FieldElement::from(314u64);
    let m  = FieldElement::from(42u64);
    let m_prime = FieldElement::from(2024u64);

    /* 声明量 */
    let C1 = g.clone().mul(&r);
    let C2 = pk.clone().mul(&r) + &g.clone().mul(&r_prime);
    let W  = g.clone().mul(&m)  + &h.clone().mul(&m_prime);

    /* 证明 + 验证 */
    let proof = prove(&g,&h,&pk,&C1,&C2,&W,&r,&r_prime,&m,&m_prime);
    assert!(verify(&g,&h,&pk,&C1,&C2,&W,&proof));
}

/* ---------------- 结构体：把先前 HybridProof + Poseidon-R1CS 拼到一起 ---------------- */
#[derive(Clone, Debug)]
pub struct FullProof {
    /* --- 旧 Hybrid 部分 --- */
    pub T1: G1, pub T2: G1, pub T3: G1,
    pub s_r: FieldElement, pub s_r_prime: FieldElement,
    pub s_m: FieldElement, pub s_m_prime: FieldElement,
    /* --- Poseidon-R1CS 部分 --- */
    pub r1cs_proof: R1CSProof,
    pub com_pk_rprime: G1,   // 对 pk^{r'} 的 Pedersen 承诺
    pub com_K:   G1,         // 对 K = Poseidon(pk^{r'}) 的 Pedersen 承诺
    pub com_c:   G1,         // 对 c  (= m-K) 的 Pedersen 承诺（公开）
    pub com_m:   G1,            // ★ 新增：对 m 的 Pedersen 承诺
}

/* -------------------- Prover -------------------- */
#[allow(clippy::too_many_arguments)]
pub fn prove_full(
    g:&G1, h:&G1, pk:&G1,
    C1:&G1, C2:&G1, W:&G1, c_val:&FieldElement,
    r:&FieldElement, r_prime:&FieldElement,
    m:&FieldElement, m_prime:&FieldElement,
    poseidon_cfg:&PoseidonConfig,      // rate=2,cap=1
    ark_fe:&[Vec<FieldElement>], mds_fe:&[Vec<FieldElement>],
    G_vec:&[G1], H_vec:&[G1],
) -> FullProof {

    /* ------------------------------------------------------------------ */
    /*  0) 预计算具体的输入点  pk^{r'}  与   K = Poseidon(pk^{r'})         */
    /* ------------------------------------------------------------------ */

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

    // println!("full_prove K_native: {}", K_native);

    // 0-3. 公开量 c = m - K      （注意同一字段内减法）
    let c_fe = m - &K_native;               // ≡ m + (-K)
    assert_eq!(c_fe, *c_val);               // 确保调用方传进来的 c 正确

    /* ------------------------------------------------------------------ */
    /*  1) Hybrid-Schnorr 片段（与之前相同）                              */
    /* ------------------------------------------------------------------ */
    let k_r       = FieldElement::random();
    let k_rprime  = FieldElement::random();
    let k_m       = FieldElement::random();
    let k_mprime  = FieldElement::random();

    let T1 = g .mul(&k_r);
    let T2 = pk.mul(&k_r) + &g.mul(&k_rprime);
    let T3 = g .mul(&k_m) + &h.mul(&k_mprime);

    /* ------------------------------------------------------------------ */
    /*  2) 创建 Poseidon-R1CS 电路                                        */
    /* ------------------------------------------------------------------ */
    // use crate::r1cs::{Prover, ConstraintSystem, LinearCombination};
    // let mut tr = Transcript::new(b"HybridPoseidon");
    // /* 把 Hybrid 的承诺也先压进 Transcript —— 防止证明拼接出错           */
    // tr.commit_point(b"T1",&T1); tr.commit_point(b"T2",&T2); tr.commit_point(b"T3",&T3);

    let mut tr = Transcript::new(b"HybridPoseidon");

    /* ① 先写入公开量 */
    tr.commit_point(b"g",  g);
    tr.commit_point(b"h",  h);
    tr.commit_point(b"pk", pk);
    tr.commit_point(b"C1", C1);
    tr.commit_point(b"C2", C2);
    tr.commit_point(b"W",  W);

    /* ② 再写入三个 Schnorr 承诺 */
    tr.commit_point(b"T1", &T1);
    tr.commit_point(b"T2", &T2);
    tr.commit_point(b"T3", &T3);

    /* ③ 现在生成 challenge */
    let c = tr.challenge_scalar(b"c");
    // 提前生成四个 Schnorr 响应（必须在 Transcript交给Prover之前完成！）
    let s_r        = &k_r       + &(c.clone() * r);
    let s_r_prime  = &k_rprime  + &(c.clone() * r_prime);
    let s_m        = &k_m       + &(c.clone() * m);
    let s_m_prime  = &k_mprime  + &(c       * m_prime);

    let mut prov = Prover::new(g, h, &mut tr);

    /* 2-1. 提交外部变量 pk^{r'}、K、c 作为 “Committed 变量” */
    let (com_pk_rprime , var_pk_rprime) = prov.commit(pk_rprime_fe.clone(), FieldElement::random());
    let (com_K         , var_K        ) = prov.commit(K_native.clone()  , FieldElement::random());
    let (com_c         , var_c        ) = prov.commit(c_fe.clone()      , FieldElement::random());

    println!("full_prove var_pk_rprime: {:?}", var_pk_rprime);
    println!("full_prove var_K: {:?}", var_K);

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

    /* 2-3. 约束   m - K - c = 0   ⇔   (m_var) - (K_var) - (c_var) = 0 */
    let (com_m, var_m) = prov.commit(m.clone(), FieldElement::random());
    prov.constrain(var_m - var_K - var_c);

    /* 2-4. 任选生成几条 debug 输出（可删） */
    // println!("pk^r'   = {}", pk_rprime_fe.to_hex());
    // println!("PoseidonK = {}", K_native.to_hex());
    // println!("c         = {}", c_fe.to_hex());

    /* 2-5. 生成 R1CS 证明 */
    let (G_vec, H_vec): (Vec<G1>, Vec<G1>) = (G_vec.into(), H_vec.into());
    let r1cs_proof = prov.prove(&G_vec.into(), &H_vec.into()).unwrap();
    // let r1cs_proof = prov.prove(&G_vec, &H_vec).unwrap();

    /* ------------------------------------------------------------------ */
    /*   3) 打包所有内容为 FullProof                                      */
    /* ------------------------------------------------------------------ */
    FullProof {
        T1, T2, T3,
        s_r,
        s_r_prime,
        s_m,
        s_m_prime,
        r1cs_proof, com_pk_rprime, com_K, com_c, com_m,
    }
}

/* ----------------------- Verifier（思路） -----------------------
   1. 复现 Hybrid Transcript → 计算同一个 c
   2. 检查三条 Schnorr 等式 (见上条回答)
   3. 用 r1cs::Verifier，把
        • com_pk_rprime 作为外部 committed 变量 0
        • poseidon_permute_r1cs 复算约束
        • 额外约束   var_m - var_K - var_c = 0
      并验证 r1cs_proof
   -------------------------------------------------------------- */
/// 验证完整证明
#[allow(clippy::too_many_arguments)]
pub fn verify_full(
    g:&G1, h:&G1, pk:&G1,
    C1:&G1, C2:&G1, W:&G1,            // 声明量
    proof:&FullProof,
    poseidon_cfg:&PoseidonConfig,
    ark_fe:&[Vec<FieldElement>], mds_fe:&[Vec<FieldElement>],
    G_vec:&[G1], H_vec:&[G1],
) -> bool {


    // /* 2) 用同一个 Transcript 创建 R1CS Verifier */
    // let mut verifier = Verifier::new(&mut tr);
    let mut tr = Transcript::new(b"HybridPoseidon");

    /* ① 公开量 */
    tr.commit_point(b"g",  g);
    tr.commit_point(b"h",  h);
    tr.commit_point(b"pk", pk);
    tr.commit_point(b"C1", C1);
    tr.commit_point(b"C2", C2);
    tr.commit_point(b"W",  W);

    /* ② Schnorr 承诺 */
    tr.commit_point(b"T1", &proof.T1);
    tr.commit_point(b"T2", &proof.T2);
    tr.commit_point(b"T3", &proof.T3);

    /* ③ 同一位置取 challenge */
    let c = tr.challenge_scalar(b"c");

    /* ④ 再创建 R1CS Verifier —— 后续逻辑不变 */
    let mut verifier = Verifier::new(&mut tr);

    /* 2-1. 依 **与 Prover 相同的顺序** 提交外部承诺 */
    let var_pk_rprime = verifier.commit(proof.com_pk_rprime.clone());
    let var_K         = verifier.commit(proof.com_K.clone());
    let var_c         = verifier.commit(proof.com_c.clone());
    let var_m         = verifier.commit(proof.com_m.clone());    // 与 prover.commit(m, …) 对应

    println!("full_verify var_pk_rprime: {:?}", var_pk_rprime);
    println!("full_verify var_K: {:?}", var_K);

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

    /* 2-3. 约束   m − K − c = 0 */
    verifier.constrain(var_m - var_K - var_c);

    /* --------------------------------------------------------- */
    /* 3) 计算 Schnorr-style challenge c 并验证三条等式           */
    /*    ※ 必须在 verifier.build() 之前读取！                    */
    /* --------------------------------------------------------- */
    

    let ok1 = g .mul(&proof.s_r) ==
              &proof.T1 + &C1.mul(&c);
    let ok2 = pk.mul(&proof.s_r) + &g.mul(&proof.s_r_prime) ==
              &proof.T2 + &C2.mul(&c);
    let ok3 = g .mul(&proof.s_m) + &h.mul(&proof.s_m_prime) ==
              &proof.T3 + &W .mul(&c);

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
    let m  = FieldElement::from(42u64);
    let m_prime = FieldElement::from(2024u64);

    /* —— 声明量 C1, C2, W —— */
    let C1 = g.clone().mul(&r);
    let C2 = pk.clone().mul(&r) + &g.clone().mul(&r_prime);
    let W  = g.clone().mul(&m)  + &h.clone().mul(&m_prime);

    /* Poseidon 参数（rate=2, capacity=1） */
    let (ark, mds) = find_poseidon_ark_and_mds(
        255, 2, 8, 57, 0);         // 示例：full=8,partial=57,alpha=5
    println!("hybrid ark[0] len: {}", ark[0].len());
    println!("hybrid mds len: {}", mds.len());
    println!("hybrid mds[0] len: {}", mds[0].len());
    let cfg = PoseidonConfig::new(
        8, 57, 5, mds.clone(), ark.clone(), 2, 1);

    /* —— 预计算 c = m - Poseidon(pk^{r'}) —— */
    let pk_rprime_pt   = pk.clone().mul(&r_prime);
    let ge_bytes = pk_rprime_pt.to_bytes(true);              // ✅ 建议用压缩
    let pk_rprime_fe = FieldElement::from_bytes(&ge_bytes[1..]).unwrap();
    // let pk_rprime_fe   = FieldElement::from_bytes(&pk_rprime_pt.to_bytes(true)).unwrap();
    let mut sponge = PoseidonSponge{
        parameters: cfg.clone(),
        state: vec![FieldElement::zero();cfg.rate+cfg.capacity],
        mode: DuplexSpongeMode::Absorbing{next_absorb_index:0}};
    sponge.absorb(0,&[pk_rprime_fe.clone()]);
    sponge.permute();
    let mut out = vec![FieldElement::zero()];
    sponge.squeeze(0,&mut out);
    let K_native = out[0].clone();
    // println!("main K_native: {}", K_native);
    let c = m.clone() - &K_native;
    println!("c: {}", c);

    /* —— Bulletproof generators —— */
    let gens = 8usize.next_power_of_two();       // 测试随便取 ≥ 8
    let G_vec = get_generators("G", 4096);
    let H_vec = get_generators("H", 4096);

    /* —— 生成证明 —— */
    let proof = prove_full(
        &g,&h,&pk,&C1,&C2,&W,&c,
        &r,&r_prime,&m,&m_prime,
        &cfg,&ark,&mds,&G_vec,&H_vec);

    println!("Proving done");

    /* —— TODO: 实现 verify_full 并 assert!(verify_full(...)) —— */
    /* —— Verify —— */
    assert!(
        verify_full(
            &g,&h,&pk,&C1,&C2,&W,
            &proof,
            &cfg,&ark,&mds,&G_vec,&H_vec
        ),
        "verification failed"
    );
}