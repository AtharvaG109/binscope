pub fn shannon_entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }

    let mut counts = [0usize; 256];
    for byte in bytes {
        counts[*byte as usize] += 1;
    }

    let len = bytes.len() as f64;
    counts
        .into_iter()
        .filter(|count| *count > 0)
        .map(|count| {
            let p = count as f64 / len;
            -p * p.log2()
        })
        .sum()
}

pub fn block_entropies(bytes: &[u8], block_size: usize) -> Vec<f64> {
    if bytes.is_empty() || block_size == 0 {
        return Vec::new();
    }

    bytes
        .chunks(block_size)
        .map(shannon_entropy)
        .collect::<Vec<_>>()
}

#[cfg(test)]
mod tests {
    use super::{block_entropies, shannon_entropy};

    #[test]
    fn entropy_is_zero_for_single_value() {
        let bytes = vec![0u8; 256];
        assert_eq!(shannon_entropy(&bytes), 0.0);
    }

    #[test]
    fn entropy_increases_for_mixed_data() {
        let bytes = (0u8..=255).collect::<Vec<_>>();
        assert!(shannon_entropy(&bytes) > 7.9);
    }

    #[test]
    fn block_entropy_splits_input() {
        let mut bytes = vec![0u8; 256];
        bytes.extend(0u8..=255);
        let blocks = block_entropies(&bytes, 256);
        assert_eq!(blocks.len(), 2);
        assert!(blocks[0] < 0.1);
        assert!(blocks[1] > 7.9);
    }

    #[test]
    fn empty_input_and_zero_block_size_return_empty_blocks() {
        assert!(block_entropies(&[], 256).is_empty());
        assert!(block_entropies(&[1, 2, 3], 0).is_empty());
    }

    #[test]
    fn final_partial_block_is_included() {
        let bytes = vec![0u8; 300];
        let blocks = block_entropies(&bytes, 256);
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0], 0.0);
        assert_eq!(blocks[1], 0.0);
    }
}
