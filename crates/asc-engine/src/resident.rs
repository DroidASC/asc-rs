//! Hosts that keep engines open (the CLI daemon, the MCP server) count what
//! those engines hold outside the cache — class graphs and resource tables
//! ([`Engine::resident_bytes`]) — against the memory budget of their shared
//! cache, closing the least recently used ones beyond a share of it.

use crate::{Engine, SharedCache};

/// The open engines' class graphs and resource tables take at most this
/// fraction (1/n) of the memory budget; the cache keeps the rest for DEX.
const RESIDENT_SHARE: usize = 2;

impl SharedCache {
    /// Of `engines`, most recently used first, the indexes of those to close
    /// so that what the rest hold fits in half the memory budget; what stays is reserved in the budget. The most recent engine
    /// stays whatever its size; without a memory cache every engine stays.
    ///
    /// Sizing waits for an engine building its class graph, so callers do
    /// not hold their own engine registry's lock across this call.
    pub fn fit_resident(&self, engines: &[&Engine]) -> Vec<usize> {
        // Without a memory cache there is no budget to fit in.
        if self.memory_capacity() == 0 {
            return Vec::new();
        }
        let sizes: Vec<usize> = engines.iter().map(|e| e.resident_bytes()).collect();
        let (held, closing) = within_share(&sizes, self.memory_capacity() / RESIDENT_SHARE);
        self.set_reserved(held);
        closing
    }
}

/// Of the resident sizes, most recently used first: the bytes of those that
/// fit in `share` together, and the indexes of the rest (to close). The
/// first stays whatever its size.
fn within_share(sizes: &[usize], share: usize) -> (usize, Vec<usize>) {
    let mut held = 0;
    let mut closing = Vec::new();
    for (i, &bytes) in sizes.iter().enumerate() {
        if i > 0 && bytes > 0 && held + bytes > share {
            closing.push(i);
        } else {
            held += bytes;
        }
    }
    (held, closing)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn beyond_the_share_least_recent_close_first() {
        assert_eq!(within_share(&[], 10), (0, vec![]));
        assert_eq!(within_share(&[50], 10), (50, vec![]), "the engine in use stays");
        assert_eq!(within_share(&[4, 5, 3, 1], 10), (10, vec![2]), "smaller older ones still fit");
        assert_eq!(within_share(&[4, 0, 0], 0), (4, vec![]), "nothing resident, nothing closed");
    }
}
