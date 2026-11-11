//! Deterministic mutation of fixture files for "malformed input never
//! panics" tests: a fixed-seed xorshift generator and the edits a fuzzer
//! starts with (bit flips, boundary integers written over offsets and
//! counts, truncation, insertion, deletion, duplicated ranges).
//!
//! ```
//! use asc_fixture::mutate::mutants;
//!
//! let seed = asc_fixture::make_dex();
//! for mutant in mutants(&seed, 0x5eed, 100) {
//!     let _ = asc_dex::Dex::parse(&mutant);
//! }
//! ```

/// xorshift64*: reproducible noise without a dependency.
#[derive(Debug, Clone)]
pub struct Rng(u64);

impl Rng {
    /// A generator from `seed` (0 is replaced, xorshift would stay at 0).
    pub fn new(seed: u64) -> Rng {
        Rng(if seed == 0 { 0x9e37_79b9_7f4a_7c15 } else { seed })
    }

    pub fn next_u64(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    /// Uniform in `0..bound`; 0 when `bound` is 0.
    pub fn below(&mut self, bound: usize) -> usize {
        if bound == 0 {
            return 0;
        }
        usize::try_from(self.next_u64() % bound as u64).expect("below a usize bound")
    }
}

/// Integers that break offset and count arithmetic.
const BOUNDARY: [u32; 12] = [0, 1, 2, 0x7f, 0x80, 0xff, 0xffff, 0x1_0000, 0x7fff_ffff, 0x8000_0000, 0xffff_fffe, u32::MAX];

/// Apply one to four random edits to `data`.
pub fn mutate(rng: &mut Rng, data: &mut Vec<u8>) {
    for _ in 0..1 + rng.below(4) {
        let len = data.len();
        match rng.below(8) {
            0 if len > 0 => {
                let at = rng.below(len);
                data[at] ^= 1 << rng.below(8);
            }
            1 if len > 0 => {
                let at = rng.below(len);
                data[at] = [0, 1, 0x7f, 0x80, 0xff][rng.below(5)];
            }
            // Offsets and counts are 4-aligned u32s in most formats.
            2 | 3 if len >= 4 => {
                let at = rng.below(len / 4) * 4;
                let value = if rng.below(4) == 0 {
                    // Near the original: off-by-one and doubled offsets.
                    let old = u32::from_le_bytes(data[at..at + 4].try_into().expect("4 bytes"));
                    [old.wrapping_add(1), old.wrapping_sub(1), old.wrapping_mul(2), old.wrapping_add(4)][rng.below(4)]
                } else {
                    BOUNDARY[rng.below(BOUNDARY.len())]
                };
                data[at..at + 4].copy_from_slice(&value.to_le_bytes());
            }
            4 if len >= 2 => {
                let at = rng.below(len / 2) * 2;
                let value = [0u16, 1, 0x7fff, 0x8000, u16::MAX][rng.below(5)];
                data[at..at + 2].copy_from_slice(&value.to_le_bytes());
            }
            5 => data.truncate(rng.below(len + 1)),
            6 if len > 0 => {
                let at = rng.below(len);
                let end = (at + 1 + rng.below(16)).min(len);
                if rng.below(2) == 0 {
                    data.drain(at..end);
                } else {
                    let copy = data[at..end].to_vec();
                    let to = rng.below(len);
                    data.splice(to..to, copy);
                }
            }
            _ => {
                let at = rng.below(len + 1);
                let byte = u8::try_from(rng.below(256)).expect("below 256");
                data.splice(at..at, std::iter::repeat_n(byte, 1 + rng.below(8)));
            }
        }
    }
}

/// `count` mutants of `seed`, each one to four edits away from it.
pub fn mutants(seed: &[u8], rng_seed: u64, count: usize) -> impl Iterator<Item = Vec<u8>> + '_ {
    let mut rng = Rng::new(rng_seed);
    (0..count).map(move |_| {
        let mut data = seed.to_vec();
        mutate(&mut rng, &mut data);
        data
    })
}
