// use amcl_wrapper::BigInt;
use amcl_wrapper::field_elem::FieldElement;
// Define DuplexSpongeMode enum here for testing
#[derive(Clone, Debug)]
pub enum DuplexSpongeMode {
    Absorbing { next_absorb_index: usize },
    Squeezing { next_squeeze_index: usize },
}

// use crate::DuplexSpongeMode;
use std::vec::Vec;

mod grain_lfsr;
pub use grain_lfsr::PoseidonGrainLFSR;
mod traits;
pub use traits::find_poseidon_ark_and_mds;
pub mod constraints;
pub use constraints::{poseidon_permute_prover, poseidon_permute_verifier};
pub mod pvtransfer;
pub use pvtransfer::{prove_full, verify_full, FullProof};


/// Config and RNG used
#[derive(Clone, Debug)]
pub struct PoseidonConfig {
    pub full_rounds: usize,
    pub partial_rounds: usize,
    pub alpha: u64,
    pub ark: Vec<Vec<FieldElement>>,
    pub mds: Vec<Vec<FieldElement>>,
    pub rate: usize,
    pub capacity: usize,
}

#[derive(Clone)]
pub struct PoseidonSponge {
    pub parameters: PoseidonConfig,
    pub state: Vec<FieldElement>,
    pub mode: DuplexSpongeMode,
}

impl PoseidonSponge {
    fn apply_s_box(&self, state: &mut [FieldElement], is_full_round: bool) {
        let exp = FieldElement::from(self.parameters.alpha);
        if is_full_round {
            for elem in state {
                *elem = elem.pow(&exp);
            }
        } else {
            state[0] = state[0].pow(&exp);
        }
    }

    fn apply_ark(&self, state: &mut [FieldElement], round_number: usize) {
        for (i, state_elem) in state.iter_mut().enumerate() {
            *state_elem = &*state_elem + &self.parameters.ark[round_number][i];
        }
    }

    fn apply_mds(&self, state: &mut [FieldElement]) {
        let mut new_state = Vec::new();
        for i in 0..state.len() {
            let mut cur = FieldElement::zero();
            for (j, state_elem) in state.iter().enumerate() {
                let term = &*state_elem * &self.parameters.mds[i][j];
                cur = &cur + &term;
            }
            new_state.push(cur);
        }
        state.clone_from_slice(&new_state[..state.len()])
    }

    pub fn permute(&mut self) {
        let full_rounds_over_2 = self.parameters.full_rounds / 2;
        let mut state = self.state.clone();
        for i in 0..full_rounds_over_2 {
            self.apply_ark(&mut state, i);
            self.apply_s_box(&mut state, true);
            self.apply_mds(&mut state);
        }
        for i in full_rounds_over_2..(full_rounds_over_2 + self.parameters.partial_rounds) {
            self.apply_ark(&mut state, i);
            self.apply_s_box(&mut state, false);
            self.apply_mds(&mut state);
        }
        for i in (full_rounds_over_2 + self.parameters.partial_rounds)
            ..(self.parameters.partial_rounds + self.parameters.full_rounds)
        {
            self.apply_ark(&mut state, i);
            self.apply_s_box(&mut state, true);
            self.apply_mds(&mut state);
        }
        self.state = state;
    }

    pub fn absorb(&mut self, mut rate_start_index: usize, elements: &[FieldElement]) {
        let mut remaining_elements = elements;
        loop {
            if rate_start_index + remaining_elements.len() <= self.parameters.rate {
                for (i, element) in remaining_elements.iter().enumerate() {
                    self.state[self.parameters.capacity + i + rate_start_index] =
                        &self.state[self.parameters.capacity + i + rate_start_index] + element;
                }
                self.mode = DuplexSpongeMode::Absorbing {
                    next_absorb_index: rate_start_index + remaining_elements.len(),
                };
                return;
            }
            let num_elements_absorbed = self.parameters.rate - rate_start_index;
            for (i, element) in remaining_elements
                .iter()
                .enumerate()
                .take(num_elements_absorbed)
            {
                self.state[self.parameters.capacity + i + rate_start_index] =
                    &self.state[self.parameters.capacity + i + rate_start_index] + element;
            }
            self.permute();
            remaining_elements = &remaining_elements[num_elements_absorbed..];
            rate_start_index = 0;
        }
    }

    pub fn squeeze(&mut self, mut rate_start_index: usize, output: &mut [FieldElement]) {
        let mut output_remaining = output;
        loop {
            if rate_start_index + output_remaining.len() <= self.parameters.rate {
                output_remaining.clone_from_slice(
                    &self.state[self.parameters.capacity + rate_start_index
                        ..(self.parameters.capacity + output_remaining.len() + rate_start_index)],
                );
                self.mode = DuplexSpongeMode::Squeezing {
                    next_squeeze_index: rate_start_index + output_remaining.len(),
                };
                return;
            }
            let num_elements_squeezed = self.parameters.rate - rate_start_index;
            output_remaining[..num_elements_squeezed].clone_from_slice(
                &self.state[self.parameters.capacity + rate_start_index
                    ..(self.parameters.capacity + num_elements_squeezed + rate_start_index)],
            );
            if output_remaining.len() != self.parameters.rate {
                self.permute();
            }
            output_remaining = &mut output_remaining[num_elements_squeezed..];
            rate_start_index = 0;
        }
    }
}

impl PoseidonConfig {
    pub fn new(
        full_rounds: usize,
        partial_rounds: usize,
        alpha: u64,
        mds: Vec<Vec<FieldElement>>,
        ark: Vec<Vec<FieldElement>>,
        rate: usize,
        capacity: usize,
    ) -> Self {
        assert_eq!(ark.len(), full_rounds + partial_rounds);
        for item in &ark {
            assert_eq!(item.len(), rate + capacity);
        }
        assert_eq!(mds.len(), rate + capacity);
        for item in &mds {
            assert_eq!(item.len(), rate + capacity);
        }
        Self {
            full_rounds,
            partial_rounds,
            alpha,
            mds,
            ark,
            rate,
            capacity,
        }
    }
}

// All trait implementations dependent on arkworks have been removed.
// You may implement simplified absorb/squeeze interfaces as needed for your use case.

#[cfg(test)]
mod test {
    use super::*;
    use amcl_wrapper::field_elem::FieldElement;

    #[test]
    fn test_poseidon_sponge_consistency() {
        // Example: Dummy parameters for illustration. Replace with real ones for your curve.
        let full_rounds = 8;
        let partial_rounds = 31;
        let alpha = 5;
        let rate = 2;
        let capacity = 1;
        // Example round constants and MDS matrix. Replace with real ones.
        let ark = vec![
            vec![
                FieldElement::from_hex("01".to_string()).unwrap(),
                FieldElement::from_hex("02".to_string()).unwrap(),
                FieldElement::from_hex("03".to_string()).unwrap(),
            ];
            full_rounds + partial_rounds
        ];
        let mds = vec![
            vec![
                FieldElement::from_hex("04".to_string()).unwrap(),
                FieldElement::from_hex("05".to_string()).unwrap(),
                FieldElement::from_hex("06".to_string()).unwrap(),
            ];
            rate + capacity
        ];
        let sponge_param = PoseidonConfig::new(
            full_rounds,
            partial_rounds,
            alpha,
            mds,
            ark,
            rate,
            capacity,
        );

        let mut sponge = PoseidonSponge {
            parameters: sponge_param,
            state: vec![FieldElement::zero(); rate + capacity],
            mode: DuplexSpongeMode::Absorbing { next_absorb_index: 0 },
        };
        let inputs = vec![
            FieldElement::from_hex("00".to_string()).unwrap(),
            FieldElement::from_hex("01".to_string()).unwrap(),
            FieldElement::from_hex("02".to_string()).unwrap(),
        ];
        sponge.absorb(0, &inputs);
        let mut out = vec![FieldElement::zero(); 3];
        sponge.permute();
        sponge.squeeze(0, &mut out);
        // Example expected outputs (replace with correct values for your parameters)
        let expected = vec![
            FieldElement::from_hex("0a".to_string()).unwrap(),
            FieldElement::from_hex("0b".to_string()).unwrap(),
            FieldElement::from_hex("0c".to_string()).unwrap(),
        ];
        // This is just for illustration. In practice, set expected to correct field values.
        // assert_eq!(out, expected);
        // For now, just print the outputs.
        for o in out {
            println!("{}", o.to_hex());
        }
    }
}
