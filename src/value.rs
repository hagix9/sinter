use crate::error::{Result, SinterError};
use std::collections::BTreeMap;
use std::fmt;

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
    List(Vec<Value>),
    Map(BTreeMap<String, Value>),
}

impl Value {
    pub fn type_name(&self) -> &'static str {
        match self {
            Value::Null => "null",
            Value::Bool(_) => "boolean",
            Value::Int(_) => "integer",
            Value::Float(_) => "float",
            Value::Str(_) => "string",
            Value::List(_) => "list",
            Value::Map(_) => "map",
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }

    pub fn as_int(&self) -> Option<i64> {
        match self {
            Value::Int(i) => Some(*i),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_list(&self) -> Option<&Vec<Value>> {
        match self {
            Value::List(l) => Some(l),
            _ => None,
        }
    }

    pub fn as_map(&self) -> Option<&BTreeMap<String, Value>> {
        match self {
            Value::Map(m) => Some(m),
            _ => None,
        }
    }

    pub fn is_null(&self) -> bool {
        matches!(self, Value::Null)
    }

    pub fn is_scalar(&self) -> bool {
        matches!(
            self,
            Value::Null | Value::Bool(_) | Value::Int(_) | Value::Float(_) | Value::Str(_)
        )
    }

    /// Canonical string formatting used when a scalar is embedded in text.
    pub fn canonical_scalar_string(&self) -> Option<String> {
        match self {
            Value::Null => Some("null".to_string()),
            Value::Bool(b) => Some(if *b { "true".into() } else { "false".into() }),
            Value::Int(i) => Some(i.to_string()),
            Value::Float(f) => Some(crate::value::format_float(*f)),
            Value::Str(s) => Some(s.clone()),
            Value::List(_) | Value::Map(_) => None,
        }
    }

    pub fn eq_value(&self, other: &Value) -> Option<bool> {
        match (self, other) {
            (Value::Null, Value::Null) => Some(true),
            (Value::Null, _) | (_, Value::Null) => None,
            (Value::Bool(a), Value::Bool(b)) => Some(a == b),
            (Value::Str(a), Value::Str(b)) => Some(a == b),
            (Value::Int(a), Value::Int(b)) => Some(a == b),
            (Value::Float(a), Value::Float(b)) => Some(a == b),
            (Value::Int(a), Value::Float(b)) => Some((*a as f64) == *b),
            (Value::Float(a), Value::Int(b)) => Some(*a == (*b as f64)),
            _ => None,
        }
    }
}

pub fn format_float(f: f64) -> String {
    if f == f.trunc() && f.is_finite() && f.abs() < 1e15 {
        format!("{:.1}", f)
    } else {
        format!("{}", f)
    }
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Value::Null => write!(f, "null"),
            Value::Bool(b) => write!(f, "{}", b),
            Value::Int(i) => write!(f, "{}", i),
            Value::Float(x) => write!(f, "{}", format_float(*x)),
            Value::Str(s) => write!(f, "\"{}\"", s.escape_default()),
            Value::List(l) => {
                write!(f, "[")?;
                for (i, v) in l.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}", v)?;
                }
                write!(f, "]")
            }
            Value::Map(m) => {
                write!(f, "{{")?;
                for (i, (k, v)) in m.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}: {}", k, v)?;
                }
                write!(f, "}}")
            }
        }
    }
}

pub fn ensure_finite_float(f: f64) -> Result<f64> {
    if f.is_finite() {
        Ok(f)
    } else {
        Err(SinterError::schema(
            "non-finite floating point values are not supported",
        ))
    }
}

pub fn has_nul(s: &str) -> bool {
    s.contains('\0')
}
