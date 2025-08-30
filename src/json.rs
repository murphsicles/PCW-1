use crate::errors::PcwError;
use serde::ser::SerializeMap;
use serde::{Serialize, Serializer};
use serde_json::{Value, to_value};
use std::collections::BTreeMap;
use unicode_normalization::UnicodeNormalization;

/// Canonical JSON serialization per §2: sorted keys, NFC strings, compact, no ws, base-10 ints, lowercase hex.
/// Uses BTreeMap for sort, custom string handling.
pub fn canonical_json<T: Serialize>(t: &T) -> Result<Vec<u8>, PcwError> {
    let val = to_value(t)?;
    let canonical = canonical_value(&val)?;
    let mut serializer = serde_json::Serializer::new(Vec::new());
    canonical.serialize(&mut serializer)?;
    Ok(serializer.into_inner())
}

/// Recursive canonical value transformation.
fn canonical_value(val: &Value) -> Result<Value, PcwError> {
    match val {
        Value::Null => Ok(Value::Null),
        Value::Bool(b) => Ok(Value::Bool(*b)),
        Value::Number(n) => Ok(Value::Number(n.clone())),
        Value::String(s) => Ok(Value::String(s.nfc().collect::<String>())), // NFC norm §2
        Value::Array(arr) => {
            let mut new_arr = Vec::with_capacity(arr.len());
            for v in arr {
                new_arr.push(canonical_value(v)?);
            }
            Ok(Value::Array(new_arr))
        }
        Value::Object(obj) => {
            let mut map = BTreeMap::new(); // Sorted keys §2
            for (k, v) in obj {
                let key = k.nfc().collect::<String>();
                map.insert(key, canonical_value(v)?);
            }
            Ok(Value::Object(map.into_iter().collect()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_canonical_json() -> Result<(), PcwError> {
        let input = json!({
            "b": 2,
            "a": 1,
            "c": "café" // Needs NFC
        });
        let bytes = canonical_json(&input)?;
        let s = String::from_utf8(bytes).unwrap();
        assert_eq!(s, r#"{"a":1,"b":2,"c":"café"}"#); // Sorted, compact, NFC (é is composed)
        Ok(())
    }

    #[test]
    fn test_no_whitespace() {
        let input = json!([1, 2, 3]);
        let bytes = canonical_json(&input).unwrap();
        assert_eq!(String::from_utf8(bytes).unwrap(), "[1,2,3]");
    }
}
