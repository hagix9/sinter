use crate::error::{Result, SinterError};
use crate::value::{ensure_finite_float, Value};
use saphyr_parser::{Event, Parser, ScalarStyle};
use std::collections::BTreeMap;
use std::collections::HashSet;

fn schema_err(msg: impl Into<String>) -> SinterError {
    SinterError::schema(msg)
}

/// Parse a YAML recipe document into the common value model.
///
/// Rejects duplicate mapping keys, aliases, anchors, merge keys, custom tags,
/// non-finite floats, and multiple documents.
pub fn parse_yaml(input: &str) -> Result<Value> {
    let mut parser = Parser::new_from_str(input);
    let mut events: Vec<Event<'_>> = Vec::new();
    loop {
        match parser.next_event() {
            Some(Ok((ev, _span))) => events.push(ev),
            Some(Err(e)) => return Err(schema_err(format!("YAML parse error: {}", e))),
            None => break,
        }
    }
    let mut p = Yp { events, pos: 0 };
    p.parse_stream()
}

struct Yp<'a> {
    events: Vec<Event<'a>>,
    pos: usize,
}

impl<'a> Yp<'a> {
    fn next(&mut self) -> Result<Event<'a>> {
        if self.pos >= self.events.len() {
            return Err(schema_err("unexpected end of YAML stream"));
        }
        let ev = self.events[self.pos].clone();
        self.pos += 1;
        Ok(ev)
    }

    fn parse_stream(&mut self) -> Result<Value> {
        match self.next()? {
            Event::StreamStart => {}
            _ => return Err(schema_err("expected YAML stream start")),
        }
        let mut docs: Vec<Value> = Vec::new();
        loop {
            match self.next()? {
                Event::DocumentStart(_) => {
                    let node = self.parse_node()?;
                    match self.next()? {
                        Event::DocumentEnd => {}
                        _ => return Err(schema_err("expected YAML document end")),
                    }
                    docs.push(node);
                }
                Event::StreamEnd => break,
                Event::Nothing => continue,
                other => return Err(schema_err(format!("unexpected YAML event: {:?}", other))),
            }
        }
        match docs.len() {
            0 => Err(schema_err("empty YAML document")),
            1 => Ok(docs.into_iter().next().unwrap()),
            _ => Err(schema_err(
                "multiple YAML documents in one file are not supported",
            )),
        }
    }

    fn parse_node(&mut self) -> Result<Value> {
        let ev = self.next()?;
        match ev {
            Event::Scalar(val, style, anchor, tag) => {
                if anchor != 0 {
                    return Err(schema_err("YAML anchors are not supported"));
                }
                let raw = val.into_owned();
                match &tag {
                    Some(t) => apply_tag(t, &raw, style),
                    None => resolve_core_scalar(&raw, style),
                }
            }
            Event::SequenceStart(anchor, tag) => {
                if anchor != 0 {
                    return Err(schema_err("YAML anchors are not supported"));
                }
                if let Some(t) = &tag {
                    if !is_seq_or_map_tag(t) {
                        return Err(schema_err(format!("unsupported YAML tag: {}", t)));
                    }
                }
                let mut items = Vec::new();
                loop {
                    match self.peek()? {
                        Event::SequenceEnd => {
                            self.next()?;
                            break;
                        }
                        _ => items.push(self.parse_node()?),
                    }
                }
                Ok(Value::List(items))
            }
            Event::MappingStart(anchor, tag) => {
                if anchor != 0 {
                    return Err(schema_err("YAML anchors are not supported"));
                }
                if let Some(t) = &tag {
                    if !is_seq_or_map_tag(t) {
                        return Err(schema_err(format!("unsupported YAML tag: {}", t)));
                    }
                }
                let mut map: BTreeMap<String, Value> = BTreeMap::new();
                let mut seen: HashSet<String> = HashSet::new();
                loop {
                    if matches!(self.peek()?, Event::MappingEnd) {
                        self.next()?;
                        break;
                    }
                    let (key, merge) = self.parse_key()?;
                    let val = self.parse_node()?;
                    if merge {
                        return Err(schema_err("YAML merge keys are not supported"));
                    }
                    if !seen.insert(key.clone()) {
                        return Err(schema_err(format!("duplicate mapping key: {}", key)));
                    }
                    map.insert(key, val);
                }
                Ok(Value::Map(map))
            }
            Event::Alias(_) => Err(schema_err("YAML aliases are not supported")),
            other => Err(schema_err(format!("unexpected YAML node: {:?}", other))),
        }
    }

    fn peek(&self) -> Result<&Event<'a>> {
        self.events
            .get(self.pos)
            .ok_or_else(|| schema_err("unexpected end of YAML stream"))
    }

    /// Parse a mapping key; returns (key, was_plain_merge_marker).
    fn parse_key(&mut self) -> Result<(String, bool)> {
        let ev = self.next()?;
        match ev {
            Event::Scalar(val, style, anchor, tag) => {
                if anchor != 0 {
                    return Err(schema_err("YAML anchors are not supported"));
                }
                let raw = val.into_owned();
                let merge = style == ScalarStyle::Plain && tag.is_none() && raw == "<<";
                let v = match &tag {
                    Some(t) => apply_tag(t, &raw, style)?,
                    None => resolve_core_scalar(&raw, style)?,
                };
                match v {
                    Value::Str(s) => Ok((s, merge)),
                    _ => Err(schema_err(
                        "mapping keys must be strings in a Sinter recipe",
                    )),
                }
            }
            Event::Alias(_) => Err(schema_err("YAML aliases are not supported")),
            _ => Err(schema_err("mapping keys must be scalars")),
        }
    }
}

fn is_seq_or_map_tag(t: &saphyr_parser::Tag) -> bool {
    t.is_yaml_core_schema() && (t.suffix == "seq" || t.suffix == "map")
}

fn apply_tag(tag: &saphyr_parser::Tag, raw: &str, style: ScalarStyle) -> Result<Value> {
    if !tag.is_yaml_core_schema() {
        return Err(schema_err(format!(
            "custom YAML tags are not supported: {}",
            tag
        )));
    }
    match tag.suffix.as_str() {
        "str" => Ok(Value::Str(raw.to_string())),
        "null" => Ok(Value::Null),
        "bool" => match raw {
            "true" | "True" | "TRUE" => Ok(Value::Bool(true)),
            "false" | "False" | "FALSE" => Ok(Value::Bool(false)),
            _ => Err(schema_err(format!("invalid !!bool value: {}", raw))),
        },
        "int" => parse_yaml_int(raw)
            .map(Value::Int)
            .ok_or_else(|| schema_err(format!("invalid !!int value: {}", raw))),
        "float" => parse_yaml_float(raw)
            .ok_or_else(|| schema_err(format!("invalid !!float value: {}", raw)))
            .and_then(|f| ensure_finite_float(f).map(Value::Float)),
        "seq" | "map" => {
            let _ = style;
            Err(schema_err(format!(
                "tag !{} cannot be applied to a scalar",
                tag.suffix
            )))
        }
        other => Err(schema_err(format!("unsupported YAML tag: {}", other))),
    }
}

pub fn resolve_core_scalar(raw: &str, style: ScalarStyle) -> Result<Value> {
    match style {
        ScalarStyle::SingleQuoted
        | ScalarStyle::DoubleQuoted
        | ScalarStyle::Literal
        | ScalarStyle::Folded => return Ok(Value::Str(raw.to_string())),
        ScalarStyle::Plain => {}
    }
    if raw.is_empty() {
        return Ok(Value::Null);
    }
    match raw {
        "null" | "Null" | "NULL" | "~" => return Ok(Value::Null),
        "true" | "True" | "TRUE" => return Ok(Value::Bool(true)),
        "false" | "False" | "FALSE" => return Ok(Value::Bool(false)),
        _ => {}
    }
    if let Some(i) = parse_yaml_int(raw) {
        return Ok(Value::Int(i));
    }
    // An integer-looking plain scalar that does not fit signed 64-bit is an
    // error, not a string. This keeps YAML and TOML semantics equivalent.
    if looks_like_integer(raw) {
        return Err(schema_err(format!(
            "integer literal out of range for signed 64-bit: {}",
            raw
        )));
    }
    if let Some(f) = parse_yaml_float(raw) {
        let f = ensure_finite_float(f)?;
        return Ok(Value::Float(f));
    }
    Ok(Value::Str(raw.to_string()))
}

/// Whether a plain scalar is lexically an integer (decimal or 0x/0o) even if it
/// is outside the signed 64-bit range.
pub fn looks_like_integer(raw: &str) -> bool {
    let (_sign, rest) = split_sign(raw);
    if rest.is_empty() {
        return false;
    }
    if let Some(hex) = rest.strip_prefix("0x").or_else(|| rest.strip_prefix("0X")) {
        return !hex.is_empty() && hex.chars().all(|c| c.is_ascii_hexdigit());
    }
    if let Some(oct) = rest.strip_prefix("0o").or_else(|| rest.strip_prefix("0O")) {
        return !oct.is_empty() && oct.chars().all(|c| c.is_ascii_digit() && c < '8');
    }
    rest.chars().all(|c| c.is_ascii_digit())
}

pub fn parse_yaml_int(raw: &str) -> Option<i64> {
    let (sign, rest) = split_sign(raw);
    let magnitude: u64 =
        if let Some(hex) = rest.strip_prefix("0x").or_else(|| rest.strip_prefix("0X")) {
            u64::from_str_radix(hex, 16).ok()?
        } else if let Some(oct) = rest.strip_prefix("0o").or_else(|| rest.strip_prefix("0O")) {
            u64::from_str_radix(oct, 8).ok()?
        } else {
            if !rest.chars().all(|c| c.is_ascii_digit()) || rest.is_empty() {
                return None;
            }
            // Parse the unsigned magnitude so i64::MIN (9223372036854775808) is
            // representable; the range check below keeps positive overflow invalid.
            rest.parse::<u64>().ok()?
        };
    if sign {
        if magnitude > (i64::MAX as u64) + 1 {
            return None;
        }
        Some((magnitude as i64).wrapping_neg())
    } else {
        if magnitude > i64::MAX as u64 {
            return None;
        }
        Some(magnitude as i64)
    }
}

pub fn parse_yaml_float(raw: &str) -> Option<f64> {
    let (sign, rest) = split_sign(raw);
    let lower = rest.to_ascii_lowercase();
    if lower == ".inf" {
        return Some(if sign {
            f64::NEG_INFINITY
        } else {
            f64::INFINITY
        });
    }
    if lower == ".nan" {
        return Some(f64::NAN);
    }
    // Reject hex/octal-looking floats and require a dot or exponent.
    if !(rest.contains('.') || rest.contains('e') || rest.contains('E')) {
        return None;
    }
    if rest.contains('x') || rest.contains('X') || rest.contains('o') || rest.contains('O') {
        return None;
    }
    let candidate = format!("{}{}", if sign { "-" } else { "" }, rest);
    candidate.parse::<f64>().ok()
}

fn split_sign(raw: &str) -> (bool, &str) {
    if let Some(r) = raw.strip_prefix('-') {
        (true, r)
    } else if let Some(r) = raw.strip_prefix('+') {
        (false, r)
    } else {
        (false, raw)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_simple_mapping() {
        let v = parse_yaml("a: 1\nb: true\nc: hello\n").unwrap();
        let m = v.as_map().unwrap();
        assert_eq!(m.get("a"), Some(&Value::Int(1)));
        assert_eq!(m.get("b"), Some(&Value::Bool(true)));
        assert_eq!(m.get("c"), Some(&Value::Str("hello".into())));
    }

    #[test]
    fn quoted_numbers_are_strings() {
        let v = parse_yaml("mode: \"0644\"\nplain: 0644\n").unwrap();
        let m = v.as_map().unwrap();
        assert_eq!(m.get("mode"), Some(&Value::Str("0644".into())));
        assert_eq!(m.get("plain"), Some(&Value::Int(644)));
    }

    #[test]
    fn rejects_aliases_and_anchors() {
        assert!(parse_yaml("a: &x 1\nb: *x\n").is_err());
        assert!(parse_yaml("a: &x 1\nb: 2\n").is_err());
    }

    #[test]
    fn rejects_duplicate_keys() {
        assert!(parse_yaml("a: 1\na: 2\n").is_err());
    }

    #[test]
    fn rejects_merge_keys() {
        assert!(parse_yaml("base: &b {x: 1}\nc:\n  <<: *b\n").is_err());
        assert!(parse_yaml("base: {x: 1}\nc:\n  <<: {y: 2}\n").is_err());
    }

    #[test]
    fn rejects_non_finite_floats() {
        assert!(parse_yaml("a: .inf\n").is_err());
        assert!(parse_yaml("a: .nan\n").is_err());
    }

    #[test]
    fn rejects_multiple_documents() {
        assert!(parse_yaml("---\na: 1\n---\nb: 2\n").is_err());
    }
}
