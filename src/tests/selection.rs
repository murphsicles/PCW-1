#[cfg(test)]
mod tests {
    use pcw_protocol::utils::{h160, sha256};
    use pcw_protocol::{PcwError, Scope, Utxo, build_reservations};
    use proptest::prelude::*;
    use secp256k1::{PublicKey, Secp256k1, SecretKey};
    use std::collections::HashSet;
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
            let per = (sum / num_utxo as u64) + 300;  // Buffer for fees
            for i in 0..num_utxo {
                u0.push(Utxo {
                    outpoint: mock_outpoint(i as u8),
                    value: per,
                    script_pubkey: mock_script.0.clone(),
                });
            }
            let split = vec![sum / num_utxo as u64; num_utxo];
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
        let secp = Secp256k1::new();
        let scope = Scope::new([1; 32], [2; 32]).unwrap();
        let secret_key = SecretKey::from_byte_array([1; 32]).unwrap();
        let recipient_anchor = PublicKey::from_secret_key(&secp, &secret_key);
        let sender_anchor = recipient_anchor;
        let mock_h160 = h160(&sha256(b"test"));
        let mock_script = create_lock_script(&Hash160(mock_h160));
        let utxo = Utxo {
            outpoint: mock_outpoint(1),
            value: 100 + 10 + 1 * (148 + 34), // Covers target + base_fee + fee
            script_pubkey: mock_script.0.clone(),
        };
        let split = vec![100];
        let (r, _, _, _) = build_reservations(
            &[utxo],
            &split,
            &scope,
            &recipient_anchor,
            &sender_anchor,
            1,
            1,
            false,
        )
        .unwrap();
        let s = r[0].as_ref().unwrap();
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].value, 100 + 10 + 1 * (148 + 34));
        Ok(())
    }

    #[test]
    fn test_select_utxos_exact_few() -> Result<(), PcwError> {
        let secp = Secp256k1::new();
        let scope = Scope::new([1; 32], [2; 32]).unwrap();
        let secret_key = SecretKey::from_byte_array([1; 32]).unwrap();
        let recipient_anchor = PublicKey::from_secret_key(&secp, &secret_key);
        let sender_anchor = recipient_anchor;
        let mock_h160 = h160(&sha256(b"test"));
        let mock_script = create_lock_script(&Hash160(mock_h160));
        let utxos = vec![
            Utxo {
                outpoint: mock_outpoint(1),
                value: 290, // <292 (needed_1), but 580 >440 (needed_2)
                script_pubkey: mock_script.0.clone(),
            },
            Utxo {
                outpoint: mock_outpoint(2),
                value: 290,
                script_pubkey: mock_script.0.clone(),
            },
        ];
        let split = vec![100]; // Single note requiring both
        let (r, _, _, _) = build_reservations(
            &utxos,
            &split,
            &scope,
            &recipient_anchor,
            &sender_anchor,
            1,
            1,
            false,
        )
        .unwrap();
        let s = r[0].as_ref().unwrap();
        assert_eq!(s.len(), 2);
        Ok(())
    }

    #[test]
    fn test_select_utxos_single_over() -> Result<(), PcwError> {
        let secp = Secp256k1::new();
        let scope = Scope::new([1; 32], [2; 32]).unwrap();
        let secret_key = SecretKey::from_byte_array([1; 32]).unwrap();
        let recipient_anchor = PublicKey::from_secret_key(&secp, &secret_key);
        let sender_anchor = recipient_anchor;
        let mock_h160 = h160(&sha256(b"test"));
        let mock_script = create_lock_script(&Hash160(mock_h160));
        let utxo = Utxo {
            outpoint: mock_outpoint(1),
            value: 200 + 10 + 1 * (148 + 34 * 2), // Buffer for 2 outputs
            script_pubkey: mock_script.0.clone(),
        };
        let split = vec![100];
        let (r, _, _, _) = build_reservations(
            &[utxo],
            &split,
            &scope,
            &recipient_anchor,
            &sender_anchor,
            1,
            1,
            false,
        )
        .unwrap();
        let s = r[0].as_ref().unwrap();
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].value, 200 + 10 + 1 * (148 + 34 * 2));
        Ok(())
    }

    #[test]
    fn test_select_utxos_few_over() -> Result<(), PcwError> {
        let secp = Secp256k1::new();
        let scope = Scope::new([1; 32], [2; 32]).unwrap();
        let secret_key = SecretKey::from_byte_array([1; 32]).unwrap();
        let recipient_anchor = PublicKey::from_secret_key(&secp, &secret_key);
        let sender_anchor = recipient_anchor;
        let mock_h160 = h160(&sha256(b"test"));
        let mock_script = create_lock_script(&Hash160(mock_h160));
        let utxos = vec![
            Utxo {
                outpoint: mock_outpoint(1),
                value: 310, // <312 (needed_1), but 620 >460 (needed_2)
                script_pubkey: mock_script.0.clone(),
            },
            Utxo {
                outpoint: mock_outpoint(2),
                value: 310,
                script_pubkey: mock_script.0.clone(),
            },
        ];
        let split = vec![120]; // Requires both, overshoots
        let (r, _, _, _) = build_reservations(
            &utxos,
            &split,
            &scope,
            &recipient_anchor,
            &sender_anchor,
            1,
            1,
            false,
        )
        .unwrap();
        let s = r[0].as_ref().unwrap();
        assert_eq!(s.len(), 2);
        Ok(())
    }

    #[test]
    fn test_select_utxos_underfunded() -> Result<(), PcwError> {
        let secp = Secp256k1::new();
        let scope = Scope::new([1; 32], [2; 32]).unwrap();
        let secret_key = SecretKey::from_byte_array([1; 32]).unwrap();
        let recipient_anchor = PublicKey::from_secret_key(&secp, &secret_key);
        let sender_anchor = recipient_anchor;
        let mock_h160 = h160(&sha256(b"test"));
        let mock_script = create_lock_script(&Hash160(mock_h160));
        let utxo = Utxo {
            outpoint: mock_outpoint(1),
            value: 50,
            script_pubkey: mock_script.0.clone(),
        };
        let split = vec![100];
        let result = build_reservations(
            &[utxo],
            &split,
            &scope,
            &recipient_anchor,
            &sender_anchor,
            1,
            1,
            false,
        );
        assert!(result.is_err());
        assert!(matches!(result, Err(PcwError::Underfunded)));
        Ok(())
    }

    #[test]
    fn test_select_utxos_dust_change() -> Result<(), PcwError> {
        let secp = Secp256k1::new();
        let scope = Scope::new([1; 32], [2; 32]).unwrap();
        let secret_key = SecretKey::from_byte_array([1; 32]).unwrap();
        let recipient_anchor = PublicKey::from_secret_key(&secp, &secret_key);
        let sender_anchor = recipient_anchor;
        let mock_h160 = h160(&sha256(b"test"));
        let mock_script = create_lock_script(&Hash160(mock_h160));
        let utxo = Utxo {
            outpoint: mock_outpoint(1),
            value: 101 + 10 + 1 * (148 + 34 * 2), // Change =1 < dust=50
            script_pubkey: mock_script.0.clone(),
        };
        let split = vec![100];
        let result = build_reservations(
            &[utxo],
            &split,
            &scope,
            &recipient_anchor,
            &sender_anchor,
            1,
            50,
            false,
        );
        assert!(result.is_err());
        assert!(matches!(result, Err(PcwError::DustChange)));
        Ok(())
    }
}
