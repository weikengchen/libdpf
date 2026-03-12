//! Distributed Point Function (DPF) implementation
//!
//! This module implements the core DPF algorithms from
//! "Function Secret Sharing: Improvements and Extensions" (Boyle et al., CCS'16)

use rand::RngCore;

use crate::aes::Prg;
use crate::block::Block;
use crate::key::DpfKey;

/// Get a specific bit from an integer (bit b from position n)
/// In C: ((unsigned int)(x) >> (n - b)) & 1
#[inline]
fn get_bit(x: u64, n: u32, b: u32) -> u8 {
    ((x >> (n - b)) & 1) as u8
}

/// DPF context for key generation and evaluation
pub struct Dpf {
    prg: Prg,
}

impl Dpf {
    /// Create a new DPF context with the given AES key
    pub fn new(key: &Block) -> Self {
        Dpf {
            prg: Prg::new(key),
        }
    }

    /// Create a DPF context with the default key from the C implementation
    pub fn with_default_key() -> Self {
        Dpf::new(&Block::new(597349, 121379))
    }

    /// Generate two DPF keys for a point function f where f(α) = 1 and f(x) = 0 for x ≠ α
    ///
    /// # Arguments
    /// * `alpha` - The special point where f(α) = 1
    /// * `n` - Domain parameter (domain size is 2^n)
    ///
    /// # Returns
    /// * `(k0, k1)` - Two DPF keys for parties 0 and 1
    pub fn gen(&self, alpha: u64, n: u8) -> (DpfKey, DpfKey) {
        let maxlayer = (n - 7) as usize;

        // Arrays to track seeds and control bits through the tree
        // s[layer][party] and t[layer][party]
        let mut s = vec![[Block::zero(), Block::zero()]; maxlayer + 1];
        let mut t = vec![[0u8, 0u8]; maxlayer + 1];

        // Correction words
        let mut scw = vec![Block::zero(); maxlayer];
        let mut tcw = vec![[0u8, 0u8]; maxlayer];

        // Initialize random seeds for both parties
        let mut rng = rand::thread_rng();
        let mut s0_bytes = [0u8; 16];
        let mut s1_bytes = [0u8; 16];
        rng.fill_bytes(&mut s0_bytes);
        rng.fill_bytes(&mut s1_bytes);
        s[0][0] = Block::from_bytes(&s0_bytes);
        s[0][1] = Block::from_bytes(&s1_bytes);

        // Set initial control bits
        t[0][0] = s[0][0].lsb();
        t[0][1] = t[0][0] ^ 1;

        // Zero LSBs of initial seeds
        s[0][0] = s[0][0].set_lsb_zero();
        s[0][1] = s[0][1].set_lsb_zero();

        // Iterate through layers
        for i in 1..=maxlayer {
            // PRG expand for both parties
            let (s0_left, s0_right, t0_left, t0_right) = self.prg.generate(&s[i - 1][0]);
            let (s1_left, s1_right, t1_left, t1_right) = self.prg.generate(&s[i - 1][1]);

            // Determine keep/lose based on alpha's bit at this position
            let alpha_bit = get_bit(alpha, n as u32, i as u32);
            let (keep, _lose): (usize, usize) = if alpha_bit == 0 {
                (0, 1) // LEFT=0, RIGHT=1
            } else {
                (1, 0)
            };

            // Compute correction word for this layer
            let s0 = [s0_left, s0_right];
            let s1 = [s1_left, s1_right];
            let t0 = [t0_left, t0_right];
            let t1 = [t1_left, t1_right];

            // Correction word for seeds
            scw[i - 1] = s0[1 - keep].xor(&s1[1 - keep]); // lose side

            // Correction bits
            tcw[i - 1][0] = t0[0] ^ t1[0] ^ alpha_bit ^ 1;
            tcw[i - 1][1] = t0[1] ^ t1[1] ^ alpha_bit;

            // Propagate for party 0
            if t[i - 1][0] == 1 {
                s[i][0] = s0[keep].xor(&scw[i - 1]);
                t[i][0] = t0[keep] ^ tcw[i - 1][keep];
            } else {
                s[i][0] = s0[keep];
                t[i][0] = t0[keep];
            }

            // Propagate for party 1
            if t[i - 1][1] == 1 {
                s[i][1] = s1[keep].xor(&scw[i - 1]);
                t[i][1] = t1[keep] ^ tcw[i - 1][keep];
            } else {
                s[i][1] = s1[keep];
                t[i][1] = t1[keep];
            }
        }

        // Compute final correction block
        // Start with a block that has LSB=1 and bit at position alpha set
        let mut final_block = Block::zero().reverse_lsb();

        // Shift to set the appropriate bit based on alpha & 127
        let shift = (alpha & 127) as u32;
        final_block = final_block.left_shift(shift);

        // Reverse LSB (now the bit pattern is set, toggle LSB back)
        final_block = final_block.reverse_lsb();

        // XOR with final seeds
        final_block = final_block.xor(&s[maxlayer][0]);
        final_block = final_block.xor(&s[maxlayer][1]);

        // Create keys for both parties
        // Party 0's key
        let k0 = DpfKey::new(
            n,
            s[0][0],
            t[0][0],
            scw.clone(),
            tcw.clone(),
            final_block,
        );

        // Party 1's key
        let k1 = DpfKey::new(
            n,
            s[0][1],
            t[0][1],
            scw,
            tcw,
            final_block,
        );

        (k0, k1)
    }

    /// Evaluate the DPF at a single point
    ///
    /// # Arguments
    /// * `key` - The DPF key
    /// * `x` - The point to evaluate at
    ///
    /// # Returns
    /// * A 128-bit block representing the evaluation result
    pub fn eval(&self, key: &DpfKey, x: u64) -> Block {
        let maxlayer = key.max_layer();

        // Current seed and control bit
        let mut s = key.s0;
        let mut t = key.t0;

        // Traverse the tree
        for i in 1..=maxlayer {
            let (sL, sR, tL, tR) = self.prg.generate(&s);

            // Apply correction if needed
            let (sL_corr, sR_corr, tL_corr, tR_corr) = if t == 1 {
                (
                    sL.xor(&key.scw[i - 1]),
                    sR.xor(&key.scw[i - 1]),
                    tL ^ key.tcw[i - 1][0],
                    tR ^ key.tcw[i - 1][1],
                )
            } else {
                (sL, sR, tL, tR)
            };

            // Choose left or right based on x's bit
            let x_bit = get_bit(x, key.n as u32, i as u32);
            if x_bit == 0 {
                s = sL_corr;
                t = tL_corr;
            } else {
                s = sR_corr;
                t = tR_corr;
            }
        }

        // Apply final corrections
        let mut res = s;
        if t == 1 {
            res = res.reverse_lsb();
        }
        if t == 1 {
            res = res.xor(&key.final_block);
        }

        res
    }

    /// Evaluate the DPF at all points in the domain
    ///
    /// # Arguments
    /// * `key` - The DPF key
    ///
    /// # Returns
    /// * A vector of 2^(n-7) blocks representing all evaluation results
    pub fn eval_full(&self, key: &DpfKey) -> Vec<Block> {
        let maxlayer = key.max_layer();
        let maxlayeritem = 1usize << maxlayer;

        // Two layers for ping-pong evaluation
        let mut s = vec![
            vec![Block::zero(); maxlayeritem],
            vec![Block::zero(); maxlayeritem],
        ];
        let mut t = vec![vec![0u8; maxlayeritem]; 2];

        // Initialize
        s[0][0] = key.s0;
        t[0][0] = key.t0;

        let mut curlayer: usize = 1;

        // Traverse the tree breadth-first
        for i in 1..=maxlayer {
            let itemnumber = 1usize << (i - 1);
            for j in 0..itemnumber {
                let (sL, sR, tL, tR) = self.prg.generate(&s[1 - curlayer][j]);

                // Apply correction if needed
                let (sL_corr, sR_corr, tL_corr, tR_corr) = if t[1 - curlayer][j] == 1 {
                    (
                        sL.xor(&key.scw[i - 1]),
                        sR.xor(&key.scw[i - 1]),
                        tL ^ key.tcw[i - 1][0],
                        tR ^ key.tcw[i - 1][1],
                    )
                } else {
                    (sL, sR, tL, tR)
                };

                // Store results
                s[curlayer][2 * j] = sL_corr;
                t[curlayer][2 * j] = tL_corr;
                s[curlayer][2 * j + 1] = sR_corr;
                t[curlayer][2 * j + 1] = tR_corr;
            }
            curlayer = 1 - curlayer;
        }

        // Compute final results
        let itemnumber = maxlayeritem;
        let mut res = Vec::with_capacity(itemnumber);

        for j in 0..itemnumber {
            let mut block = s[1 - curlayer][j];

            if t[1 - curlayer][j] == 1 {
                block = block.reverse_lsb();
            }
            if t[1 - curlayer][j] == 1 {
                block = block.xor(&key.final_block);
            }

            res.push(block);
        }

        res
    }
}

/// Convenience function to generate DPF keys
pub fn gen(alpha: u64, n: u8) -> (DpfKey, DpfKey) {
    let dpf = Dpf::with_default_key();
    dpf.gen(alpha, n)
}

/// Convenience function to evaluate DPF at a point
pub fn eval(key: &DpfKey, x: u64) -> Block {
    let dpf = Dpf::with_default_key();
    dpf.eval(key, x)
}

/// Convenience function for full domain evaluation
pub fn eval_full(key: &DpfKey) -> Vec<Block> {
    let dpf = Dpf::with_default_key();
    dpf.eval_full(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gen_basic() {
        let dpf = Dpf::with_default_key();
        let (k0, k1) = dpf.gen(26943, 16);
        
        assert_eq!(k0.n, 16);
        assert_eq!(k1.n, 16);
        assert_eq!(k0.scw.len(), k0.max_layer());
        assert_eq!(k1.scw.len(), k1.max_layer());
    }

    #[test]
    fn test_eval_xor_property() {
        // The XOR of evaluations from both keys should give the point function value
        let dpf = Dpf::with_default_key();
        let alpha: u64 = 26943;
        let n: u8 = 16;
        
        let (k0, k1) = dpf.gen(alpha, n);

        // Evaluate at alpha - should get non-zero result when XOR'd
        let res0 = dpf.eval(&k0, alpha);
        let res1 = dpf.eval(&k1, alpha);
        let xor_result = res0.xor(&res1);
        
        // At alpha, the XOR should have a non-zero pattern (the special point)
        // The result encodes the position within the block
        assert!(!xor_result.is_equal(&Block::zero()));
    }

    #[test]
    fn test_eval_zero_at_other_points() {
        let dpf = Dpf::with_default_key();
        let alpha: u64 = 26943;
        let n: u8 = 16;
        
        let (k0, k1) = dpf.gen(alpha, n);

        // Evaluate at a different point - should get zero when XOR'd
        for x in [0u64, 128, 1000, 50000].iter() {
            if *x != alpha {
                let res0 = dpf.eval(&k0, *x);
                let res1 = dpf.eval(&k1, *x);
                let xor_result = res0.xor(&res1);
                assert!(xor_result.is_equal(&Block::zero()), 
                    "Expected zero at x={}, got {:?}", x, xor_result);
            }
        }
    }

    #[test]
    fn test_eval_full() {
        let dpf = Dpf::with_default_key();
        let alpha: u64 = 26943;
        let n: u8 = 16;
        
        let (k0, k1) = dpf.gen(alpha, n);

        let res0 = dpf.eval_full(&k0);
        let res1 = dpf.eval_full(&k1);

        let expected_len = 1 << (n - 7);
        assert_eq!(res0.len(), expected_len as usize);
        assert_eq!(res1.len(), expected_len as usize);

        // Check that XOR results match point-by-point evaluation
        for (i, (r0, r1)) in res0.iter().zip(res1.iter()).enumerate() {
            let xor_result = r0.xor(r1);
            // Check if this is the block containing alpha
            let block_start = (i * 128) as u64;
            let block_end = block_start + 128;
            
            if alpha >= block_start && alpha < block_end {
                // This block should be non-zero
                assert!(!xor_result.is_equal(&Block::zero()),
                    "Block {} containing alpha should be non-zero", i);
            } else {
                // This block should be zero
                assert!(xor_result.is_equal(&Block::zero()),
                    "Block {} not containing alpha should be zero", i);
            }
        }
    }

    #[test]
    fn test_key_serialization_preserves_evaluation() {
        let dpf = Dpf::with_default_key();
        let alpha: u64 = 12345;
        let n: u8 = 16;
        
        let (k0, k1) = dpf.gen(alpha, n);

        // Serialize and deserialize
        let k0_bytes = k0.to_bytes();
        let k0_restored = DpfKey::from_bytes(&k0_bytes).unwrap();
        let k1_bytes = k1.to_bytes();
        let k1_restored = DpfKey::from_bytes(&k1_bytes).unwrap();

        // Evaluations should match
        for x in [0u64, alpha, 50000].iter() {
            let res0_orig = dpf.eval(&k0, *x);
            let res0_rest = dpf.eval(&k0_restored, *x);
            let res1_orig = dpf.eval(&k1, *x);
            let res1_rest = dpf.eval(&k1_restored, *x);

            assert_eq!(res0_orig, res0_rest, "k0 evaluation mismatch at x={}", x);
            assert_eq!(res1_orig, res1_rest, "k1 evaluation mismatch at x={}", x);
        }
    }
}