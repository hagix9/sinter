use crate::error::{Result, SinterError};
use crate::value::{ensure_finite_float, Value};
use std::collections::BTreeMap;

/// Parse a TOML recipe document into the common value model.
///
/// Rejects TOML datetime values. Values map directly onto the Sinter value model.
pub fn parse_toml(input: &str) -> Result<Value> {
    let parsed: toml::Value = input
        .parse()
        .map_err(|e| SinterError::schema(format!("TOML parse error: {}", e)))?;
    convert(&parsed)
}

fn convert(v: &toml::Value) -> Result<Value> {
    match v {
        toml::Value::String(s) => Ok(Value::Str(s.clone())),
        toml::Value::Integer(i) => Ok(Value::Int(*i)),
        toml::Value::Float(f) => ensure_finite_float(*f).map(Value::Float),
        toml::Value::Boolean(b) => Ok(Value::Bool(*b)),
        toml::Value::Datetime(_) => Err(SinterError::schema(
            "TOML datetime values are not supported",
        )),
        toml::Value::Array(a) => {
            let mut out = Vec::with_capacity(a.len());
            for item in a {
                out.push(convert(item)?);
            }
            Ok(Value::List(out))
        }
        toml::Value::Table(t) => {
            let mut map = BTreeMap::new();
            for (k, val) in t.iter() {
                map.insert(k.clone(), convert(val)?);
            }
            Ok(Value::Map(map))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_basic_types() {
        let v = parse_toml("a = 1\nb = true\nc = \"x\"\nd = [1, 2]\n").unwrap();
        let m = v.as_map().unwrap();
        assert_eq!(m.get("a"), Some(&Value::Int(1)));
        assert_eq!(m.get("b"), Some(&Value::Bool(true)));
        assert_eq!(m.get("c"), Some(&Value::Str("x".into())));
        assert_eq!(
            m.get("d"),
            Some(&Value::List(vec![Value::Int(1), Value::Int(2)]))
        );
    }

    #[test]
    fn rejects_datetime() {
        assert!(parse_toml("x = 1979-05-27T07:32:00Z\n").is_err());
        assert!(parse_toml("x = 1979-05-27\n").is_err());
        assert!(parse_toml("x = 07:32:00\n").is_err());
    }

    #[test]
    fn rejects_non_finite() {
        assert!(parse_toml("x = inf\n").is_err());
        assert!(parse_toml("x = nan\n").is_err());
    }
}
