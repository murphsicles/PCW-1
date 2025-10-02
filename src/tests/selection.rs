#[cfg(test)]
mod tests {
    use super::*;
    use pcw_protocol::{PcwError, Scope, selection::Utxo, build_reservations};
    use pcw_protocol::keys::{AnchorKeypair, IdentityKeypair};
    use pcw_protocol::utils::{h160, sha256};
    use secp256k1::{PublicKey, Secp256k1, SecretKey};
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
            let secp = Secp256k1::new();
            let scope = Scope::new([1; 32], [2; 32]).unwrap();
            let secret_key = SecretKey::from_byte_array([1; 32]).unwrap();
            let recipient_anchor = PublicKey::from_secret_key(&secp, &secret_key);
            let sender_anchor = recipient_anchor;
            let mock_h160 = h160(&sha256(b"test"));
            let mock_script = create_lock_script(&Hash160(mock_h160));
            let mut u0 = vec![];
            let per = sum / num_utxo as u64;
            for i in 0..num_utxo {
                u0.push(Utxo {
                    outpoint: mock_outpoint(i as u8),
                    value: per,
                    script_pubkey: mock_script.0.clone(),
                });
            }
            let split = vec![per; num_utxo];
            let (r, _, _, _) = build_reservations(&u0, &split, &scope, &recipient_anchor, &sender_anchor, 1, 50, false).unwrap();
            prop_assert_eq!(r.len(), num_utxo);
            let mut used = HashSet::new();
            for (i, s_i) in r.iter().enumerate() {
                if let Some(si) = s_i {
                    for u in si {
                        prop_assert!(!used.contains(&u.outpoint.hash));
                        used.insert(u.outpoint.hash);
                    }
                } else {
                    prop_assert!(false, "Reservation {} is None", i);
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
            value: 100 + 10 + 1 * (148 + 34), // Covers target + base_fee + fee
            script_pubkey: mock_script.0.clone(),
        };
        let mut used = HashSet::new();
        let target = 100;
        let feerate_floor = 1;
        let dust = 1;
        let s = select_utxos(&[utxo], &mut used, target, feerate_floor, dust)?;
        assert!(s.is_some());
        assert_eq!(s.unwrap().len(), 1);
        assert_eq!(s.unwrap()[0].value, 100 + 10 + 1 * (148 + 34));
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
                script_pubkey: mock_script.0.clone(),
            },
            Utxo {
                outpoint: mock_outpoint(2),
                value: 60,
                script_pubkey: mock_script.0.clone(),
            },
        ];
        let mut used = HashSet::new();
        let target = 100; // Requires both UTXOs
        let feerate_floor = 1;
        let dust = 1;
        let s = select_utxos(&utxos, &mut used, target, feerate_floor, dust)?;
        assert!(s.is_some());
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
            script_pubkey: mock_script.0.clone(),
        };
        let mut used = HashSet::new();
        let target = 100;
        let feerate_floor = 1;
        let dust = 1;
        let s = select_utxos(&[utxo], &mut used, target, feerate_floor, dust)?;
        assert!(s.is_some());
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
                script_pubkey: mock_script.0.clone(),
            },
            Utxo {
                outpoint: mock_outpoint(2),
                value: 80,
                script_pubkey: mock_script.0.clone(),
            },
        ];
        let mut used = HashSet::new();
        let target = 120; // Requires both, overshoots
        let feerate_floor = 1;
        let dust = 1;
        let s = select_utxos(&utxos, &mut used, target, feerate_floor, dust)?;
        assert!(s.is_some());
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
            script_pubkey: mock_script.0.clone(),
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
            script_pubkey: mock_script.0.clone(),
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
