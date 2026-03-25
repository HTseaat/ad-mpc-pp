use crate::poseidon::{PoseidonConfig, find_poseidon_ark_and_mds};
use crate::r1cs::{ConstraintSystem, LinearCombination, Prover, Variable, Verifier};
use amcl_wrapper::field_elem::FieldElement;
use merlin::Transcript;
use hex;
use amcl_wrapper::group_elem::GroupElement;
use amcl_wrapper::group_elem_g1::{G1Vector, G1};
use amcl_wrapper::group_elem::GroupElementVector; // 确保导入 trait

pub fn poseidon_permute_prover(
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

pub fn poseidon_permute_verifier(
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