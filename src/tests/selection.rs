#[cfg(test)]
mod tests {
    use super::*;
    use sv::messages::OutPoint;
    use proptest::prelude::*;

    fn mock_outpoint(id: u8) -> OutPoint {
        OutPoint { txid: [id; 32], vout: id as u32 }
    }

    proptest! {
        #[test]
        fn prop_build_reservations(sum in 1000u64..10000, num_utxo in 5..20usize) {
            let mut u0 = vec![];
            let per = sum / num_utxo as u64;
            for i in 0..num_utxo {
                u0.push(Utxo { outpoint: mock_outpoint(i as u8), value: per, script_pubkey: vec![] });
            }
            let split = vec![per; num_utxo];
            let r = build_reservations(&u0, &split, 1, 1, 3, 5, true).unwrap();
            prop_assert_eq!(r.len(), num_utxo);
            let mut used = HashSet::new();
            for (_, s_i) in r {
                for u in &s_i {
                    prop_assert!(!used.contains(&u.outpoint));
                    used.insert(u.outpoint.clone());
                }
            }
        }
    }

    #[test]
    fn test_select_inputs_exact_single() -> Result<(), PcwError> {
        let utxo = Utxo { outpoint: mock_outpoint(1), value: 100 + 148 + 34, script_pubkey: vec![] };
        let used = HashSet::new();
        let s = select_inputs(&[utxo], &used, 100, 1, 1, 3, 5)?;
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].value, 100 + 148 + 34);
        Ok(())
    }

    // Additional tests for stage B (exact few), C (single over), D (few over), rejects
}
