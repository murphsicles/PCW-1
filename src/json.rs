//! Module for canonical JSON serialization in the PCW-1 protocol.
//!
//! This module implements canonical JSON as per §2, ensuring:
//! - Sorted keys in objects.
//! - NFC-normalized strings.
//! - Compact output without whitespace.
//! - Lowercase hex encoding.
//! - No floating-point numbers.
use crate::errors::PcwError;
use crate::utils::nfc_normalize;
use serde_json::{Map, Value};
use std::collections::BTreeMap;

pub fn canonical_json(v: &Value) -> Result<Vec<u8>, PcwError> {
    match v {
        Value::Null => Ok(b"null".to_vec()),
        Value::Bool(true) => Ok(b"true".to_vec()),
        Value::Bool(false) => Ok(b"false".to_vec()),
        Value::Number(n) => {
            if !n.is_i64() && !n.is_u64() {
                return Err(PcwError::Other(
                    "Non-integer numbers not allowed §2".to_string(),
                ));
            }
            Ok(n.to_string().as_bytes().to_vec())
        }
        Value::String(s) => {
            let s_nfc = nfc_normalize(s);
            let mut result = vec![b'"'];
            for c in s_nfc.chars() {
                match c {
                    '\x08' => result.extend_from_slice(b"\\b"),
                    '\x09' => result.extend_from_slice(b"\\t"),
                    '\x0a' => result.extend_from_slice(b"\\n"),
                    '\x0c' => result.extend_from_slice(b"\\f"),
                    '\x0d' => result.extend_from_slice(b"\\r"),
                    '"' => result.extend_from_slice(b"\\\""),
                    '\\' => result.extend_from_slice(b"\\\\"),
                    _ if c.is_control() => {
                        let u = c as u32;
                        result.extend_from_slice(format!("\\u{:04x}", u).as_bytes());
                    }
                    _ => result.extend_from_slice(c.encode_utf8(&mut [0; 4]).as_bytes()),
                }
            }
            result.push(b'"');
            Ok(result)
        }
        Value::Array(arr) => {
            let mut result = vec![b'['];
            for (i, v) in arr.iter().enumerate() {
                if i > 0 {
                    result.push(b',');
                }
                result.extend_from_slice(&canonical_json(v)?);
            }
            result.push(b']');
            Ok(result)
        }
        Value::Object(obj) => {
            let mut result = vec![b'{'];
            let sorted: BTreeMap<_, _> = obj.iter().map(|(k, v)| (nfc_normalize(k), v)).collect();
            for (i, (k, v)) in sorted.iter().enumerate() {
                if i > 0 {
                    result.push(b',');
                }
                result.extend_from_slice(&canonical_json(&Value::String(k.to_string()))?);
                result.push(b':');
                result.extend_from_slice(&canonical_json(v)?);
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
    fn test_canonical_json_primitives() -> Result<(), PcwError> {
        let v = json!(null);
        assert_eq!(canonical_json(&v)?, b"null");
        let v = json!(true);
        assert_eq!(canonical_json(&v)?, b"true");
        let v = json!(false);
        assert_eq!(canonical_json(&v)?, b"false");
        let v = json!(42);
        assert_eq!(canonical_json(&v)?, b"42");
        let v = json!("test");
        assert_eq!(canonical_json(&v)?, b"\"test\"");
        Ok(())
    }

    #[test]
    fn test_canonical_json_float_rejected() {
        let v = json!(42.5);
        let result = canonical_json(&v);
        assert!(result.is_err());
        assert!(matches!(result, Err(PcwError::Other(msg)) if msg.contains("Non-integer numbers")));
    }

    #[test]
    fn test_canonical_json_array() -> Result<(), PcwError> {
        let v = json!([1, 2, 3]);
        assert_eq!(canonical_json(&v)?, b"[1,2,3]");
        let v = json!([]);
        assert_eq!(canonical_json(&v)?, b"[]");
        Ok(())
    }

    #[test]
    fn test_canonical_json_object() -> Result<(), PcwError> {
        let v = json!({ "b": 2, "a": 1 });
        assert_eq!(canonical_json(&v)?, b"{\"a\":1,\"b\":2}");
        Ok(())
    }

    #[test]
    fn test_canonical_json_nested() -> Result<(), PcwError> {
        let nested = json!({
            "a": [1, {"b": "0xff", "c": 3}],
            "d": {"e": 4}
        });
        let result = canonical_json(&nested)?;
        assert_eq!(
            result,
            b"{\"a\":[1,{\"b\":\"0xff\",\"c\":3}],\"d\":{\"e\":4}}",
        );
        Ok(())
    }

    #[test]
    fn test_canonical_json_nfc() -> Result<(), PcwError> {
        let v = json!({ "café": 1, "cafe": 2 });
        assert_eq!(
            canonical_json(&v)?,
            b"{\"cafe\":2,\"caf\u{00e9}\":1}",
        );
        Ok(())
    }

    #[test]
    fn test_canonical_json_escape() -> Result<(), PcwError> {
        let v = json!({ "quote": "\"", "slash": "\\", "tab": "\t" });
        assert_eq!(
            canonical_json(&v)?,
            b"{\"quote\":\"\\\"\",\"slash\":\"\\\\\",\"tab\":\"\\t\"}"
        );
        Ok(())
    }
}
