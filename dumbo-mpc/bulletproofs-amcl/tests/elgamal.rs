//! 证明知识：存在标量 r 使得 C1 = g·r （BLS12-381 G1 群中）
//! 采用 Schnorr PoK，Fiat–Shamir 到 Merlin Transcript。
//!
//! - `prove_dlog`  生成证明 (T, s)
//! - `verify_dlog` 验证证明
//!
//! 依赖：amcl_wrapper + merlin（项目已带依赖）


use bulletproofs_amcl::transcript::TranscriptProtocol;  
use std::ops::Mul;      
use amcl_wrapper::field_elem::FieldElement;
use amcl_wrapper::group_elem::GroupElement;
use amcl_wrapper::group_elem_g1::G1;
use merlin::Transcript;

/// Schnorr 证明结构体：T = g·k, s = k + c·r
#[derive(Clone, Debug)]
struct SchnorrProof {
    T: G1,
    s: FieldElement,
}

/// ------------  证明端  ------------
fn prove_dlog(g: &G1, C1: &G1, r: &FieldElement) -> SchnorrProof {
    // 1) 随机挑选 k
    let k = FieldElement::random();
    let T = g.mul(&k);

    // 2) Fiat–Shamir 获取挑战 c = H(g, C1, T)
    let mut transcript = Transcript::new(b"Schnorr-DL");
    transcript.commit_point(b"g", g);
    transcript.commit_point(b"C1", C1);
    transcript.commit_point(b"T", &T);
    let c = transcript.challenge_scalar(b"c"); // FieldElement

    // 3) 计算响应 s = k + c·r
    let s = &k + &(c * r);

    SchnorrProof { T, s }
}

/// ------------  验证端  ------------
fn verify_dlog(g: &G1, C1: &G1, proof: &SchnorrProof) -> bool {
    // 1) 重新计算挑战
    let mut transcript = Transcript::new(b"Schnorr-DL");
    transcript.commit_point(b"g", g);
    transcript.commit_point(b"C1", C1);
    transcript.commit_point(b"T", &proof.T);
    let c = transcript.challenge_scalar(b"c");

    // 2) 检查 g·s == T + C1·c
    let lhs = g.mul(&proof.s);                 // g·s
    let rhs = &proof.T + &C1.mul(&c);          // T + C1·c
    lhs == rhs
}

/// ------------------  单元测试  ------------------
#[test]
fn test_schnorr_dlog_proof() {
    // 生成元 g  &  witness r
    let g = G1::from_msg_hash(b"elgamal_generator");
    let r = FieldElement::from(42u64);                // 例子里取固定 42，也可随机
    // let C1 = g.mul(&r);                               // 声明量 C1 = g·r
    let C1 = g.clone().mul(&r); // clone 是必须的
    let proof = prove_dlog(&g, &C1, &r); // OK

    // 证明
    let proof = prove_dlog(&g, &C1, &r);

    // 验证
    assert!(verify_dlog(&g, &C1, &proof));
}

/// -------- 证明结构 --------
#[derive(Clone, Debug)]
struct ElgamalProof {
    T1: G1,
    T2: G1,
    s_r: FieldElement,
    s_m: FieldElement,
}

/// --------  证明端  --------
/// witness: (m, r)
/// statement: (g, h, pk, C1, C2)
fn prove_elgamal(
    g: &G1,
    h: &G1,
    pk: &G1,
    C1: &G1,
    C2: &G1,
    m: &FieldElement,
    r: &FieldElement,
) -> ElgamalProof {
    // 1) 随机掩码
    let k_r = FieldElement::random();
    let k_m = FieldElement::random();

    // 2) 计算承诺
    let T1 = g.mul(&k_r);
    let T2 = pk.mul(&k_r) + &h.mul(&k_m);

    // 3) Fiat–Shamir 挑战
    let mut transcript = Transcript::new(b"Elgamal-PK");
    transcript.commit_point(b"g", g);
    transcript.commit_point(b"h", h);
    transcript.commit_point(b"pk", pk);
    transcript.commit_point(b"C1", C1);
    transcript.commit_point(b"C2", C2);
    transcript.commit_point(b"T1", &T1);
    transcript.commit_point(b"T2", &T2);
    let c = transcript.challenge_scalar(b"c");

    // 4) 响应
    let s_r = &k_r + &(c.clone() * r);
    let s_m = &k_m + &(c * m);

    ElgamalProof { T1, T2, s_r, s_m }
}

/// --------  验证端  --------
fn verify_elgamal(
    g: &G1,
    h: &G1,
    pk: &G1,
    C1: &G1,
    C2: &G1,
    proof: &ElgamalProof,
) -> bool {
    // 1) 重新计算挑战
    let mut transcript = Transcript::new(b"Elgamal-PK");
    transcript.commit_point(b"g", g);
    transcript.commit_point(b"h", h);
    transcript.commit_point(b"pk", pk);
    transcript.commit_point(b"C1", C1);
    transcript.commit_point(b"C2", C2);
    transcript.commit_point(b"T1", &proof.T1);
    transcript.commit_point(b"T2", &proof.T2);
    let c = transcript.challenge_scalar(b"c");

    // 2) 检查两条等式
    let check1 = g.mul(&proof.s_r) == &proof.T1 + &C1.mul(&c);
    let check2 = pk.mul(&proof.s_r) + &h.mul(&proof.s_m) == &proof.T2 + &C2.mul(&c);

    check1 && check2
}

/// -------------- 单元测试 --------------
#[test]
fn test_elgamal_zkp() {
    // 生成独立基
    let g  = G1::from_msg_hash(b"generator_g");
    let h  = G1::from_msg_hash(b"generator_h");  // 必须线性独立于 g
    let sk = FieldElement::from(123u64);         // 私钥
    let pk = g.clone().mul(&sk);                         // 公钥

    // 明文 & 随机 r
    let m = FieldElement::from(42u64);
    let r = FieldElement::from(77u64);

    // ElGamal 加密
    let C1 = g.clone().mul(&r);                        // g^r
    let C2 = pk.clone().mul(&r) + &h.clone().mul(&m);          // pk^r + h^m

    // 生成证明
    let proof = prove_elgamal(&g, &h, &pk, &C1, &C2, &m, &r);

    // 验证
    assert!(verify_elgamal(&g, &h, &pk, &C1, &C2, &proof));
}