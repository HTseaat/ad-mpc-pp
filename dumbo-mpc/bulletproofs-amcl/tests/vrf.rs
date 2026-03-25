//! Simple EC‑VRF (IETF style) using amcl_wrapper primitives
//!
//! 输出 β = sk · H(msg) ∈ G1
//! 证明 π = (c , s) 其中
//!     c = H(pk , P , β , R1 , R2)      （Merlin transcript）
//!     s = k + c·sk
//! 验证者只需检查  c == H(pk , P , β , s·G − c·pk , s·P − c·β)



use std::ops::Mul;
use amcl_wrapper::group_elem_g1::{G1Vector, G1};
use amcl_wrapper::group_elem::GroupElementVector; // 确保导入 trait
use amcl_wrapper::field_elem::FieldElement;
use amcl_wrapper::group_elem::GroupElement;
use bulletproofs_amcl::transcript::TranscriptProtocol;
use merlin::Transcript;

/// Schnorr‑style proof (challenge, response)
#[derive(Clone, Debug)]
pub struct Proof {
    pub c: FieldElement,
    pub s: FieldElement,
}

/// Secret / public key pair -------------------------------------------------
pub struct Secret {
    sk: FieldElement,
}
pub struct Public {
    pk: G1,
}

/// Helper: fixed generator chosen deterministically from a domain tag
fn generator() -> G1 {
    G1::from_msg_hash(b"generator")
}

/// ----------------------------- KeyGen ------------------------------------
impl Secret {
    pub fn keygen() -> (Self, Public) {
        let sk = FieldElement::random();
        let pk = generator().mul(&sk);
        (Self { sk }, Public { pk })
    }

    /// --------------------------- Prove -----------------------------------
    pub fn prove(&self, msg: &[u8]) -> (G1, Proof) {
        let g = generator();
        let pk = g.clone().mul(&self.sk);

        // 1) H(msg) → curve point
        let P   = G1::from_msg_hash(msg);
        let β   = P.clone().mul(&self.sk);

        // 2) 随机 nonce
        let k   = FieldElement::random();
        let R1  = g.mul(&k);
        let R2  = P.clone().mul(&k);

        // 3) Fiat–Shamir 取挑战 c
        let mut tr = Transcript::new(b"VRF");
        tr.commit_point(b"pk",   &pk);
        tr.commit_point(b"P",    &P);
        tr.commit_point(b"beta", &β);
        tr.commit_point(b"R1",   &R1);
        tr.commit_point(b"R2",   &R2);
        let c = tr.challenge_scalar(b"c");

        // 4) 响应
        let s = k + c.clone() * &self.sk;

        (β, Proof { c, s })
    }
}

/// ------------------------------ Verify ------------------------------------
impl Public {
    pub fn verify(&self, msg: &[u8], beta: &G1, proof: &Proof) -> bool {
        let g = generator();
        let P = G1::from_msg_hash(msg);

        // u = s·G − c·pk
        let u = g.mul(&proof.s) + &self.pk.clone().mul(&(-proof.c.clone()));
        // v = s·P − c·β
        let v = P.clone().mul(&proof.s) + &beta.mul(&(-proof.c.clone()));

        // 重新计算挑战
        let mut tr = Transcript::new(b"VRF");
        tr.commit_point(b"pk",   &self.pk);
        tr.commit_point(b"P",    &P);
        tr.commit_point(b"beta", beta);
        tr.commit_point(b"R1",   &u);
        tr.commit_point(b"R2",   &v);
        let c_exp = tr.challenge_scalar(b"c");

        &c_exp == &proof.c
    }
}

/// ------------------------------- Tests ------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vrf_prove_verify_ok() {
        let (secret, public) = Secret::keygen();
        let msg = b"vrf";

        let (beta, proof) = secret.prove(msg);
        assert!(public.verify(msg, &beta, &proof));
    }

    #[test]
    fn vrf_verify_fails_if_beta_tampered() {
        let (secret, public) = Secret::keygen();
        let msg = b"test";

        let (beta, proof) = secret.prove(msg);
        // 改动 β → 应验证失败
        let beta_bad = beta + &generator().mul(&FieldElement::from(1u64));
        assert!(!public.verify(msg, &beta_bad, &proof));
    }
}