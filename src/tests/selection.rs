#[cfg(test)]
mod tests {
    use super::*;
    use pcw_protocol::selection::{select_utxos, Utxo};
    use pcw_protocol::utils::{h160, sha256};
    use std::collections::HashSet;
    use proptest::prelude::*;
    use sv::messages::OutPoint;
    use sv::transaction::p2pkh::create_lock_script;
    use sv::util::{Hash160, Hash256};

    fn mock_outpoint(id: u8) -> OutPoint {
        OutPoint {
            hash: Hash256(sha256(&[id])),
            index: id as u32,
        }
    }

    proptest! {
        #[test]
        fn prop_build_reservations(sum in 1000u64..10000, num_utxo in 5..20usize) {
            let mock_h160 = h160(&sha256(b"test"));
            let mock_script = create_lock_script(&Hash160(mock_h160));
            let mut u0 = vec![];
            let per = sum / num_utxo as u64;
            for i in 0..num_utxo {
                u0.push(Utxo {
                    outpoint: mock_outpoint(i as u8),
                    value: per,
                    script_pubkey: mock_script.to_bytes(),
                });
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
    fn test_select_utxos_exact_single() -> Result<(), PcwError> {
        let mock_h160 = h160(&sha256(b"test"));
        let mock_script = create_lock_script(&Hash160(mock_h160));
        let utxo = Utxo {
            outpoint: mock_outpoint(1),
            value: 100 + 148 + 34, // Covers target + fees
            script_pubkey: mock_script.to_bytes(),
        };
        let mut used = HashSet::new();
        let target = 100;
        let feerate_floor = 1;
        let dust = 1;
        let s = select_utxos(&[utxo], &mut used, target, feerate_floor, dust)?;
        assert_eq!(s.unwrap().len(), 1);
        assert_eq!(s.unwrap()[0].value, 100 + 148 + 34);
        assert_eq!(used.len(), 1);
        Ok(())
    }

    #[test]
    fn test_select_utxos_exact_few() -> Result<(), PcwError> {
        let mock_h160 = h160(&sha256(b"test"));
        let mock_script = create_lock_script(&Hash160(mock_h160));
        let utxos = vec![
            Utxo {
                outpoint: mock_outpoint(1),
                value: 60,
                script_pubkey: mock_script.to_bytes(),
            },
            Utxo {
                outpoint: mock_outpoint(2),
                value: 60,
                script_pubkey: mock_script.to_bytes(),
            },
        ];
        let mut used = HashSet::new();
        let target = 100; // Requires both UTXOs
        let feerate_floor = 1;
        let dust = 1;
        let s = select_utxos(&utxos, &mut used, target, feerate_floor, dust)?;
        assert_eq!(s.unwrap().len(), 2);
        assert_eq!(used.len(), 2);
        Ok(())
    }

    #[test]
    fn test_select_utxos_single_over() -> Result<(), PcwError> {
        let mock_h160 = h160(&sha256(b"test"));
        let mock_script = create_lock_script(&Hash160(mock_h160));
        let utxo = Utxo {
            outpoint: mock_outpoint(1),
            value: 200, // Overshoots target
            script_pubkey: mock_script.to_bytes(),
        };
        let mut used = HashSet::new();
        let target = 100;
        let feerate_floor = 1;
        let dust = 1;
        let s = select_utxos(&[utxo], &mut used, target, feerate_floor, dust)?;
        assert_eq!(s.unwrap().len(), 1);
        assert_eq!(s.unwrap()[0].value, 200);
        assert_eq!(used.len(), 1);
        Ok(())
    }

    #[test]
    fn test_select_utxos_few_over() -> Result<(), PcwError> {
        let mock_h160 = h160(&sha256(b"test"));
        let mock_script = create_lock_script(&Hash160(mock_h160));
        let utxos = vec![
            Utxo {
                outpoint: mock_outpoint(1),
                value: 80,
                script_pubkey: mock_script.to_bytes(),
            },
            Utxo {
                outpoint: mock_outpoint(2),
                value: 80,
                script_pubkey: mock_script.to_bytes(),
            },
        ];
        let mut used = HashSet::new();
        let target = 120; // Requires both, overshoots
        let feerate_floor = 1;
        let dust = 1;
        let s = select_utxos(&utxos, &mut used, target, feerate_floor, dust)?;
        assert_eq!(s.unwrap().len(), 2);
        assert_eq!(used.len(), 2);
        Ok(())
    }

    #[test]
    fn test_select_utxos_underfunded() -> Result<(), PcwError> {
        let mock_h160 = h160(&sha256(b"test"));
        let mock_script = create_lock_script(&Hash160(mock_h160));
        let utxo = Utxo {
            outpoint: mock_outpoint(1),
            value: 50,
            script_pubkey: mock_script.to_bytes(),
        };
        let mut used = HashSet::new();
        let target = 100;
        let feerate_floor = 1;
        let dust = 1;
        let s = select_utxos(&[utxo], &mut used, target, feerate_floor, dust)?;
        assert!(s.is_none());
        assert_eq!(used.len(), 0);
        Ok(())
    }

    #[test]
    fn test_select_utxos_dust_change() -> Result<(), PcwError> {
        let mock_h160 = h160(&sha256(b"test"));
        let mock_script = create_lock_script(&Hash160(mock_h160));
        let utxo = Utxo {
            outpoint: mock_outpoint(1),
            value: 101, // Causes dust change
            script_pubkey: mock_script.to_bytes(),
        };
        let mut used = HashSet::new();
        let target = 100;
        let feerate_floor = 1;
        let dust = 50;
        let result = select_utxos(&[utxo], &mut used, target, feerate_floor, dust);
        assert!(result.is_err());
        assert!(matches!(result, Err(PcwError::DustChange)));
        assert_eq!(used.len(), 0);
        Ok(())
    }
}
