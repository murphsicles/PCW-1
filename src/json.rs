//! Module for canonical JSON serialization in the PCW-1 protocol.
//!
//! This module implements canonical JSON serialization as per §2, ensuring sorted keys,
//! NFC-normalized strings, compact output, and lowercase hex for strings starting with '0x'.
//! Numbers must be base-10 integers, and floating-point numbers are rejected.
use crate::errors::PcwError;
use crate::utils::nfc_normalize;
use serde_json::{Map, Number, Value};
use std::collections::BTreeMap;

/// Canonical JSON serialization (§2).
pub fn canonical_json<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, PcwError> {
    let val = serde_json::to_value(value)?;
    canonical_value(&val)
}

/// Canonical JSON value serialization (§2).
fn canonical_value(val: &Value) -> Result<Vec<u8>, PcwError> {
    match val {
        Value::Null => Ok(b"null".to_vec()),
        Value::Bool(true) => Ok(b"true".to_vec()),
        Value::Bool(false) => Ok(b"false".to_vec()),
        Value::Number(n) => {
            if !n.is_i64() && !n.is_u64() {
                return Err(PcwError::Other("Non-integer numbers not allowed §2".to_string()));
            }
            Ok(n.to_string().as_bytes().to_vec())
        }
        Value::String(s) => {
            let s = if s.starts_with("0x") {
                s.to_lowercase()
            } else {
                nfc_normalize(s)
            };
            let escaped = serde_json::to_string(&s)?;
            Ok(escaped.as_bytes().to_vec())
        }
        Value::Array(arr) => {
            let mut result = vec![b'['];
            for (i, v) in arr.iter().enumerate() {
                if i > 0 {
                    result.push(b',');
                }
                result.extend_from_slice(&canonical_value(v)?);
            }
            result.push(b']');
            Ok(result)
        }
        Value::Object(obj) => {
            let mut result = vec![b'{'];
            let sorted: BTreeMap<_, _> = obj
                .iter()
                .map(|(k, v)| (nfc_normalize(k), v))
                .collect();
            for (i, (k, v)) in sorted.iter().enumerate() {
                if i > 0 {
                    result.push(b',');
                }
                let escaped_key = serde_json::to_string(k)?;
                result.extend_from_slice(escaped_key.as_bytes());
                result.push(b':');
                result.extend_from_slice(&canonical_value(v)?);
            }
            result.push(b'}');
            Ok(result)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_canonical_json_string() -> Result<(), PcwError> {
        let s = "test".to_string();
        let result = canonical_json(&s)?;
        assert_eq!(result, b"\"test\"");
        Ok(())
    }

    #[test]
    fn test_canonical_json_hex() -> Result<(), PcwError> {
        let s = "0xABCDEF".to_string();
        let result = canonical_json(&s)?;
        assert_eq!(result, b"\"0xabcdef\"");
        Ok(())
    }

    #[test]
    fn test_canonical_json_object() -> Result<(), PcwError> {
        let obj: Map<String, Value> = serde_json::from_str(r#"{"b": 2, "a": 1}"#)?;
        let result = canonical_json(&obj)?;
        assert_eq!(result, b"{\"a\":1,\"b\":2}");
        Ok(())
    }

    #[test]
    fn test_canonical_json_array() -> Result<(), PcwError> {
        let arr = vec![1, 2, 3];
        let result = canonical_json(&arr)?;
        assert_eq!(result, b"[1,2,3]");
        Ok(())
    }

    #[test]
    fn test_canonical_json_float_rejected() {
        let float = json!(1.5);
        let result = canonical_json(&float);
        assert!(result.is_err());
        assert!(matches!(result, Err(PcwError::Other(msg)) if msg.contains("Non-integer numbers")));
    }

    #[test]
    fn test_canonical_json_nested() -> Result<(), PcwError> {
        let nested = json!({
            "a": [1, {"b": "0xFF", "c": 3}],
            "d": {"e": 4}
        });
        let result = canonical_json(&nested)?;
        assert_eq!(result, b"{\"a\":[1,{\"b\":\"0xff\",\"c\":3}],\"d\":{\"e\":4}}");
        Ok(())
    }

    #[test]
    fn test_canonical_json_empty() -> Result<(), PcwError> {
        let empty_obj: Map<String, Value> = Map::new();
        let result = canonical_json(&empty_obj)?;
        assert_eq!(result, b"{}");
        let empty_arr: Vec<Value> = vec![];
        let result = canonical_json(&empty_arr)?;
        assert_eq!(result, b"[]");
        Ok(())
    }

    #[test]
    fn test_canonical_json_null() -> Result<(), PcwError> {
        let null = json!(null);
        let result = canonical_json(&null)?;
        assert_eq!(result, b"null");
        Ok(())
    }
}
