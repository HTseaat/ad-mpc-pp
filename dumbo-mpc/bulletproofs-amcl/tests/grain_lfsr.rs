#![allow(dead_code)]

use amcl_wrapper::field_elem::FieldElement;
use ark_std::vec::Vec;

pub struct PoseidonGrainLFSR {
    pub prime_num_bits: u64,

    pub state: [bool; 80],
    pub head: usize,
}

#[allow(unused_variables)]
impl PoseidonGrainLFSR {
    pub fn new(
        is_sbox_an_inverse: bool,
        prime_num_bits: u64,
        state_len: u64,
        num_full_rounds: u64,
        num_partial_rounds: u64,
    ) -> Self {
        let mut state = [false; 80];

        // b0, b1 describes the field
        state[1] = true;

        // b2, ..., b5 describes the S-BOX
        if is_sbox_an_inverse {
            state[5] = true;
        } else {
            state[5] = false;
        }

        // b6, ..., b17 are the binary representation of n (prime_num_bits)
        {
            let mut cur = prime_num_bits;
            for i in (6..=17).rev() {
                state[i] = cur & 1 == 1;
                cur >>= 1;
            }
        }

        // b18, ..., b29 are the binary representation of t (state_len, rate + capacity)
        {
            let mut cur = state_len;
            for i in (18..=29).rev() {
                state[i] = cur & 1 == 1;
                cur >>= 1;
            }
        }

        // b30, ..., b39 are the binary representation of R_F (the number of full rounds)
        {
            let mut cur = num_full_rounds;
            for i in (30..=39).rev() {
                state[i] = cur & 1 == 1;
                cur >>= 1;
            }
        }

        // b40, ..., b49 are the binary representation of R_P (the number of partial rounds)
        {
            let mut cur = num_partial_rounds;
            for i in (40..=49).rev() {
                state[i] = cur & 1 == 1;
                cur >>= 1;
            }
        }

        // b50, ..., b79 are set to 1
        for i in 50..=79 {
            state[i] = true;
        }

        let head = 0;

        let mut res = Self {
            prime_num_bits,
            state,
            head,
        };
        res.init();
        res
    }

    pub fn get_bits(&mut self, num_bits: usize) -> Vec<bool> {
        let mut res = Vec::new();

        for _ in 0..num_bits {
            // Obtain the first bit
            let mut new_bit = self.update();

            // Loop until the first bit is true
            while new_bit == false {
                // Discard the second bit
                let _ = self.update();
                // Obtain another first bit
                new_bit = self.update();
            }

            // Obtain the second bit
            res.push(self.update());
        }

        res
    }

    pub fn get_field_elements_rejection_sampling(
        &mut self,
        num_elems: usize,
    ) -> Vec<FieldElement> {
        let mut res = Vec::new();
        for _ in 0..num_elems {
            loop {
                // let bits = self.get_bits(self.prime_num_bits as usize);
                // let mut bytes = bits
                let mut bits = self.get_bits(self.prime_num_bits as usize);
                bits.reverse();
                let mut bytes = bits
                    .chunks(8)
                    .map(|chunk| {
                        let mut result = 0u8;
                        for (i, bit) in chunk.iter().enumerate() {
                            result |= u8::from(*bit) << i;
                        }
                        result
                    })
                    .collect::<Vec<u8>>();

                // Pad to 48 bytes if necessary
                if bytes.len() < 48 {
                    let mut padded_bytes = vec![0u8; 48 - bytes.len()];
                    padded_bytes.extend_from_slice(&bytes);
                    bytes = padded_bytes;
                }

                if let Ok(f) = FieldElement::from_bytes(&bytes) {
                    res.push(f);
                    break;
                }
            }
        }
        res
    }

    pub fn get_field_elements_mod_p(&mut self, num_elems: usize) -> Vec<FieldElement> {
        let mut res = Vec::new();
        for _ in 0..num_elems {
            let mut bits = self.get_bits(self.prime_num_bits as usize);
            bits.reverse();
            let bytes = bits
                .chunks(8)
                .map(|chunk| {
                    let mut result = 0u8;
                    for (i, bit) in chunk.iter().enumerate() {
                        result |= u8::from(*bit) << i;
                    }
                    result
                })
                .collect::<Vec<u8>>();
            res.push(FieldElement::from_bytes(&bytes).unwrap());
        }
        res
    }

    #[inline]
    fn update(&mut self) -> bool {
        let new_bit = self.state[(self.head + 62) % 80]
            ^ self.state[(self.head + 51) % 80]
            ^ self.state[(self.head + 38) % 80]
            ^ self.state[(self.head + 23) % 80]
            ^ self.state[(self.head + 13) % 80]
            ^ self.state[self.head];
        self.state[self.head] = new_bit;
        self.head += 1;
        self.head %= 80;

        new_bit
    }

    fn init(&mut self) {
        for _ in 0..160 {
            let new_bit = self.state[(self.head + 62) % 80]
                ^ self.state[(self.head + 51) % 80]
                ^ self.state[(self.head + 38) % 80]
                ^ self.state[(self.head + 23) % 80]
                ^ self.state[(self.head + 13) % 80]
                ^ self.state[self.head];
            self.state[self.head] = new_bit;
            self.head += 1;
            self.head %= 80;
        }
    }
}

#[cfg(test)]
mod test {
    use super::PoseidonGrainLFSR;
    use amcl_wrapper::field_elem::FieldElement;

    #[test]
    fn test_grain_lfsr_consistency() {
        let mut lfsr = PoseidonGrainLFSR::new(false, 255, 3, 8, 31);
        println!("FieldElement = {:?}", FieldElement::from_hex("A".to_string()).unwrap());
        

        assert_eq!(
            lfsr.get_field_elements_rejection_sampling(1)[0],
            FieldElement::from_hex("30B3AEAE57A92F7430CCFBC5F3047FD09AB3ECB99DC388F93ABA7B93A9DAF33B".to_string()).unwrap()
        );
        assert_eq!(
            lfsr.get_field_elements_rejection_sampling(1)[0],
            FieldElement::from_hex("12DE33DA2925BB79DA58AE9675F14C23AE61FE149831864290FD18A325252C71".to_string()).unwrap()
        );
    }
}
