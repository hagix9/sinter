use crate::value::{format_float, Value};
use std::collections::BTreeMap;

#[derive(Debug, Clone)]
pub struct EvalVal {
    pub val: Option<Value>,
    pub sensitive: bool,
}

impl EvalVal {
    pub fn known(v: Value) -> Self {
        EvalVal {
            val: Some(v),
            sensitive: false,
        }
    }
    pub fn known_sensitive(v: Value) -> Self {
        EvalVal {
            val: Some(v),
            sensitive: true,
        }
    }
    pub fn unknown() -> Self {
        EvalVal {
            val: None,
            sensitive: false,
        }
    }
    pub fn is_unknown(&self) -> bool {
        self.val.is_none()
    }
    pub fn mark_sensitive(mut self) -> Self {
        self.sensitive = true;
        self
    }
}

#[derive(Debug, Clone)]
pub struct ExprError(pub String);

impl ExprError {
    /// A safe structural category for this error, with no body-derived values.
    /// Used when the originating resource/data is sensitive (DESIGN §31).
    pub fn category(&self) -> &'static str {
        let m = self.0.as_str();
        if m.contains("invalid number literal") || m.contains("invalid integer literal") {
            "invalid numeric literal"
        } else if m.contains("unterminated string") {
            "unterminated string"
        } else if m.contains("bare names are not allowed") {
            "unqualified reference"
        } else if m.contains("unexpected character") {
            "unexpected character"
        } else if m.contains("unexpected token") {
            "unexpected token"
        } else if m.contains("undefined variable") {
            "undefined variable"
        } else if m.contains("undefined register") {
            "undefined register"
        } else if m.contains("unknown command result field") {
            "unknown result field"
        } else if m.contains("not available in this context") {
            "value not available in this context"
        } else if m.contains("trailing tokens") {
            "trailing tokens"
        } else if m.contains("expected") {
            "parse error"
        } else if m.contains("type") {
            "type error"
        } else {
            "expression error"
        }
    }
}

impl std::fmt::Display for ExprError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

fn err<T>(msg: impl Into<String>) -> Result<T, ExprError> {
    Err(ExprError(msg.into()))
}

// ---------------------------------------------------------------------------
// AST
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub enum Expr {
    Or(Box<Expr>, Box<Expr>),
    And(Box<Expr>, Box<Expr>),
    Not(Box<Expr>),
    Cmp(Box<Expr>, CmpOp, Box<Expr>),
    Var(String),
    Fact(Vec<String>),
    Register(String, String),
    Item,
    ResultField(String),
    TemplateVar(String),
    Str(String),
    Int(i64),
    Float(f64),
    Bool(bool),
    Null,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CmpOp {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

// ---------------------------------------------------------------------------
// Lexer
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Ident(String),
    Str(String),
    Int(i64),
    Float(f64),
    True,
    False,
    Null,
    And,
    Or,
    Not,
    EqEq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    LParen,
    RParen,
    End,
}

struct Lexer<'a> {
    chars: Vec<char>,
    pos: usize,
    _src: &'a str,
}

impl<'a> Lexer<'a> {
    fn new(src: &'a str) -> Self {
        Lexer {
            chars: src.chars().collect(),
            pos: 0,
            _src: src,
        }
    }

    fn peek(&self) -> Option<char> {
        self.chars.get(self.pos).copied()
    }

    fn next(&mut self) -> Option<char> {
        let c = self.peek();
        if c.is_some() {
            self.pos += 1;
        }
        c
    }

    fn skip_ws(&mut self) {
        while let Some(c) = self.peek() {
            if c.is_whitespace() {
                self.pos += 1;
            } else {
                break;
            }
        }
    }

    fn token(&mut self) -> Result<Tok, ExprError> {
        self.skip_ws();
        let c = match self.peek() {
            None => return Ok(Tok::End),
            Some(c) => c,
        };
        match c {
            '(' => {
                self.pos += 1;
                return Ok(Tok::LParen);
            }
            ')' => {
                self.pos += 1;
                return Ok(Tok::RParen);
            }
            '&' => {
                self.pos += 1;
                if self.next() == Some('&') {
                    return Ok(Tok::And);
                }
                return err("expected &&");
            }
            '|' => {
                self.pos += 1;
                if self.next() == Some('|') {
                    return Ok(Tok::Or);
                }
                return err("expected ||");
            }
            '!' => {
                self.pos += 1;
                if self.peek() == Some('=') {
                    self.pos += 1;
                    return Ok(Tok::Ne);
                }
                return Ok(Tok::Not);
            }
            '=' => {
                self.pos += 1;
                if self.next() == Some('=') {
                    return Ok(Tok::EqEq);
                }
                return err("expected ==");
            }
            '<' => {
                self.pos += 1;
                if self.peek() == Some('=') {
                    self.pos += 1;
                    return Ok(Tok::Le);
                }
                return Ok(Tok::Lt);
            }
            '>' => {
                self.pos += 1;
                if self.peek() == Some('=') {
                    self.pos += 1;
                    return Ok(Tok::Ge);
                }
                return Ok(Tok::Gt);
            }
            '"' | '\'' => return self.lex_string(c),
            _ => {}
        }
        if c.is_ascii_digit() {
            return self.lex_number();
        }
        if c.is_alphabetic() || c == '_' {
            return self.lex_ident();
        }
        err(format!("unexpected character in expression: {:?}", c))
    }

    fn lex_string(&mut self, quote: char) -> Result<Tok, ExprError> {
        self.pos += 1;
        let mut s = String::new();
        loop {
            match self.next() {
                None => return err("unterminated string literal"),
                Some('\\') => {
                    let esc = self
                        .next()
                        .ok_or_else(|| ExprError("unterminated escape".into()))?;
                    match esc {
                        'n' => s.push('\n'),
                        't' => s.push('\t'),
                        'r' => s.push('\r'),
                        '\\' => s.push('\\'),
                        '"' => s.push('"'),
                        '\'' => s.push('\''),
                        other => {
                            s.push('\\');
                            s.push(other);
                        }
                    }
                }
                Some(c) if c == quote => break,
                Some(c) => s.push(c),
            }
        }
        Ok(Tok::Str(s))
    }

    fn lex_number(&mut self) -> Result<Tok, ExprError> {
        let start = self.pos;
        while let Some(c) = self.peek() {
            if c.is_ascii_digit() || c == '.' || c == 'e' || c == 'E' || c == '+' || c == '-' {
                self.pos += 1;
            } else {
                break;
            }
        }
        let raw: String = self.chars[start..self.pos].iter().collect();
        if raw.contains('.') || raw.contains('e') || raw.contains('E') {
            raw.parse::<f64>()
                .map(Tok::Float)
                .map_err(|_| ExprError(format!("invalid number literal: {}", raw)))
        } else {
            raw.parse::<i64>()
                .map(Tok::Int)
                .map_err(|_| ExprError(format!("invalid integer literal: {}", raw)))
        }
    }

    fn lex_ident(&mut self) -> Result<Tok, ExprError> {
        let start = self.pos;
        while let Some(c) = self.peek() {
            if c.is_alphanumeric() || c == '_' || c == '.' {
                self.pos += 1;
            } else {
                break;
            }
        }
        let raw: String = self.chars[start..self.pos].iter().collect();
        match raw.as_str() {
            "true" => Ok(Tok::True),
            "false" => Ok(Tok::False),
            "null" => Ok(Tok::Null),
            _ => Ok(Tok::Ident(raw)),
        }
    }
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

pub fn parse_expr(src: &str) -> Result<Expr, ExprError> {
    let mut lx = Lexer::new(src);
    let mut toks = Vec::new();
    loop {
        let t = lx.token()?;
        let end = t == Tok::End;
        toks.push(t);
        if end {
            break;
        }
    }
    let mut p = P { toks, pos: 0 };
    let e = p.parse_or()?;
    if p.peek() != &Tok::End {
        return err("trailing tokens in expression");
    }
    Ok(e)
}

struct P {
    toks: Vec<Tok>,
    pos: usize,
}

impl P {
    fn peek(&self) -> &Tok {
        self.toks.get(self.pos).unwrap_or(&Tok::End)
    }
    fn bump(&mut self) -> Tok {
        let t = self.toks.get(self.pos).cloned().unwrap_or(Tok::End);
        self.pos += 1;
        t
    }

    fn parse_or(&mut self) -> Result<Expr, ExprError> {
        let mut left = self.parse_and()?;
        while self.peek() == &Tok::Or {
            self.bump();
            let right = self.parse_and()?;
            left = Expr::Or(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_and(&mut self) -> Result<Expr, ExprError> {
        let mut left = self.parse_not()?;
        while self.peek() == &Tok::And {
            self.bump();
            let right = self.parse_not()?;
            left = Expr::And(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_not(&mut self) -> Result<Expr, ExprError> {
        if self.peek() == &Tok::Not {
            self.bump();
            let inner = self.parse_not()?;
            return Ok(Expr::Not(Box::new(inner)));
        }
        self.parse_cmp()
    }

    fn parse_cmp(&mut self) -> Result<Expr, ExprError> {
        let left = self.parse_primary()?;
        let op = match self.peek() {
            Tok::EqEq => CmpOp::Eq,
            Tok::Ne => CmpOp::Ne,
            Tok::Lt => CmpOp::Lt,
            Tok::Le => CmpOp::Le,
            Tok::Gt => CmpOp::Gt,
            Tok::Ge => CmpOp::Ge,
            _ => return Ok(left),
        };
        self.bump();
        let right = self.parse_primary()?;
        Ok(Expr::Cmp(Box::new(left), op, Box::new(right)))
    }

    fn parse_primary(&mut self) -> Result<Expr, ExprError> {
        match self.bump() {
            Tok::LParen => {
                let e = self.parse_or()?;
                if self.bump() != Tok::RParen {
                    return err("expected )");
                }
                Ok(e)
            }
            Tok::Str(s) => Ok(Expr::Str(s)),
            Tok::Int(i) => Ok(Expr::Int(i)),
            Tok::Float(f) => Ok(Expr::Float(f)),
            Tok::True => Ok(Expr::Bool(true)),
            Tok::False => Ok(Expr::Bool(false)),
            Tok::Null => Ok(Expr::Null),
            Tok::Ident(name) => resolve_ref(&name),
            other => err(format!("unexpected token in expression: {:?}", other)),
        }
    }
}

fn resolve_ref(name: &str) -> Result<Expr, ExprError> {
    if name == "item" {
        return Ok(Expr::Item);
    }
    let parts: Vec<&str> = name.split('.').collect();
    if parts.iter().any(|p| p.is_empty()) {
        return err(format!("invalid reference: {}", name));
    }
    match parts[0] {
        "vars" => {
            if parts.len() != 2 {
                return err(format!("invalid variable reference: {}", name));
            }
            Ok(Expr::Var(parts[1].to_string()))
        }
        "facts" => {
            let path: Vec<String> = parts[1..].iter().map(|s| s.to_string()).collect();
            Ok(Expr::Fact(path))
        }
        "registers" => {
            if parts.len() != 3 {
                return err(format!("invalid register reference: {}", name));
            }
            Ok(Expr::Register(parts[1].to_string(), parts[2].to_string()))
        }
        "result" => {
            if parts.len() != 2 {
                return err(format!("invalid result reference: {}", name));
            }
            Ok(Expr::ResultField(parts[1].to_string()))
        }
        "template" => {
            if parts.len() != 2 {
                return err(format!("invalid template reference: {}", name));
            }
            Ok(Expr::TemplateVar(parts[1].to_string()))
        }
        _ => err(format!(
            "bare names are not allowed; use an explicit namespace: {}",
            name
        )),
    }
}

// ---------------------------------------------------------------------------
// Scope
// ---------------------------------------------------------------------------

pub struct Scope<'a> {
    pub vars: Option<&'a BTreeMap<String, EvalVal>>,
    pub facts: Option<&'a crate::facts::Facts>,
    pub registers: Option<&'a BTreeMap<String, EvalVal>>,
    pub item: Option<&'a EvalVal>,
    pub result: Option<&'a BTreeMap<String, EvalVal>>,
    pub template: Option<&'a BTreeMap<String, EvalVal>>,
}

impl<'a> Scope<'a> {
    pub fn empty() -> Self {
        Scope {
            vars: None,
            facts: None,
            registers: None,
            item: None,
            result: None,
            template: None,
        }
    }

    pub fn static_scope(vars: &'a BTreeMap<String, EvalVal>, item: Option<&'a EvalVal>) -> Self {
        Scope {
            vars: Some(vars),
            facts: None,
            registers: None,
            item,
            result: None,
            template: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Evaluator
// ---------------------------------------------------------------------------

pub fn eval_expr(e: &Expr, scope: &Scope) -> Result<EvalVal, ExprError> {
    match e {
        Expr::Or(a, b) => eval_or(a, b, scope),
        Expr::And(a, b) => eval_and(a, b, scope),
        Expr::Not(a) => {
            let v = eval_expr(a, scope)?;
            match v.val {
                None => Ok(EvalVal {
                    val: None,
                    sensitive: v.sensitive,
                }),
                Some(Value::Bool(b)) => Ok(EvalVal {
                    val: Some(Value::Bool(!b)),
                    sensitive: v.sensitive,
                }),
                Some(other) => err(format!(
                    "operator ! requires boolean, got {}",
                    other.type_name()
                )),
            }
        }
        Expr::Cmp(a, op, b) => eval_cmp(a, *op, b, scope),
        Expr::Var(name) => {
            let vars = match scope.vars {
                Some(v) => v,
                None => {
                    return err(format!(
                        "vars are not available in this context (vars.{})",
                        name
                    ))
                }
            };
            match vars.get(name) {
                Some(v) => Ok(v.clone()),
                None => err(format!("undefined variable: vars.{}", name)),
            }
        }
        Expr::Fact(path) => {
            let facts = match scope.facts {
                Some(f) => f,
                None => {
                    return err(
                        "facts may not be used to form static identifiers or in this context"
                            .to_string(),
                    )
                }
            };
            facts.lookup(path)
        }
        Expr::Register(name, field) => {
            let regs = match scope.registers {
                Some(r) => r,
                None => {
                    return err(format!(
                        "registers are not available in this context (registers.{}.{})",
                        name, field
                    ))
                }
            };
            match regs.get(name) {
                Some(v) => register_field(v, field),
                None => err(format!("undefined register: {}", name)),
            }
        }
        Expr::Item => match scope.item {
            Some(v) => Ok(v.clone()),
            None => err("item is not available in this context"),
        },
        Expr::ResultField(field) => {
            let res = match scope.result {
                Some(r) => r,
                None => return err(format!("result.{} is not available in this context", field)),
            };
            // Enforce output completeness consistently: reading result.stdout or
            // result.stderr when the captured stream is incomplete is an error,
            // never a silently truncated/NULL value. The complete flags remain
            // readable so recipes can test them explicitly.
            let complete_key = match field.as_str() {
                "stdout" => Some("stdout_complete"),
                "stderr" => Some("stderr_complete"),
                _ => None,
            };
            if let Some(k) = complete_key {
                if let Some(cv) = res.get(k) {
                    if matches!(cv.val, Some(Value::Bool(false))) {
                        return err(format!(
                            "result.{} is incomplete (truncated or non-UTF-8) and cannot be used",
                            field
                        ));
                    }
                }
            }
            match res.get(field) {
                Some(v) => Ok(v.clone()),
                None => err(format!("unknown command result field: result.{}", field)),
            }
        }
        Expr::TemplateVar(name) => {
            let tmpl = match scope.template {
                Some(t) => t,
                None => {
                    return err(format!(
                        "template.{} is not available in this context",
                        name
                    ))
                }
            };
            match tmpl.get(name) {
                Some(v) => Ok(v.clone()),
                None => err(format!("undefined template variable: template.{}", name)),
            }
        }
        Expr::Str(s) => Ok(EvalVal::known(Value::Str(s.clone()))),
        Expr::Int(i) => Ok(EvalVal::known(Value::Int(*i))),
        Expr::Float(f) => Ok(EvalVal::known(Value::Float(*f))),
        Expr::Bool(b) => Ok(EvalVal::known(Value::Bool(*b))),
        Expr::Null => Ok(EvalVal::known(Value::Null)),
    }
}

fn register_field(v: &EvalVal, field: &str) -> Result<EvalVal, ExprError> {
    match &v.val {
        None => Ok(EvalVal {
            val: None,
            sensitive: v.sensitive,
        }),
        Some(Value::Map(m)) => {
            // Command output that is incomplete (truncated or non-UTF-8) must
            // not be silently used as an empty/truncated value (DESIGN §10.5).
            let complete_key = match field {
                "stdout" => Some("stdout_complete"),
                "stderr" => Some("stderr_complete"),
                _ => None,
            };
            if let Some(k) = complete_key {
                if matches!(m.get(k), Some(Value::Bool(false))) {
                    return err(format!(
                        "register output field {} is incomplete (truncated or non-UTF-8) and cannot be used",
                        field
                    ));
                }
            }
            match m.get(field) {
                Some(fv) => Ok(EvalVal {
                    val: Some(fv.clone()),
                    sensitive: v.sensitive,
                }),
                None => err(format!("unknown command result field: {}", field)),
            }
        }
        Some(other) => err(format!(
            "register value is not a command result: {}",
            other.type_name()
        )),
    }
}

fn eval_cmp(a: &Expr, op: CmpOp, b: &Expr, scope: &Scope) -> Result<EvalVal, ExprError> {
    let va = eval_expr(a, scope)?;
    let vb = eval_expr(b, scope)?;
    let sensitive = va.sensitive || vb.sensitive;
    match (va.val, vb.val) {
        (None, _) | (_, None) => Ok(EvalVal {
            val: None,
            sensitive,
        }),
        (Some(x), Some(y)) => {
            let result = compare(&x, op, &y)?;
            Ok(EvalVal {
                val: Some(Value::Bool(result)),
                sensitive,
            })
        }
    }
}

fn compare(x: &Value, op: CmpOp, y: &Value) -> Result<bool, ExprError> {
    match op {
        CmpOp::Eq => x.eq_value(y).ok_or_else(|| {
            ExprError(format!(
                "cannot compare {} and {}",
                x.type_name(),
                y.type_name()
            ))
        }),
        CmpOp::Ne => x.eq_value(y).map(|b| !b).ok_or_else(|| {
            ExprError(format!(
                "cannot compare {} and {}",
                x.type_name(),
                y.type_name()
            ))
        }),
        CmpOp::Lt | CmpOp::Le | CmpOp::Gt | CmpOp::Ge => match (x, y) {
            (Value::Int(a), Value::Int(b)) => Ok(ord_cmp(*a, *b, op)),
            (Value::Float(a), Value::Float(b)) => Ok(ord_cmp(*a, *b, op)),
            (Value::Int(a), Value::Float(b)) => Ok(ord_cmp(*a as f64, *b, op)),
            (Value::Float(a), Value::Int(b)) => Ok(ord_cmp(*a, *b as f64, op)),
            (Value::Str(a), Value::Str(b)) => {
                let ord = a.cmp(b);
                Ok(match op {
                    CmpOp::Lt => ord.is_lt(),
                    CmpOp::Le => ord.is_le(),
                    CmpOp::Gt => ord.is_gt(),
                    CmpOp::Ge => ord.is_ge(),
                    _ => unreachable!(),
                })
            }
            _ => Err(ExprError(format!(
                "ordering is not defined for {} and {}",
                x.type_name(),
                y.type_name()
            ))),
        },
    }
}

fn ord_cmp<T: PartialOrd>(a: T, b: T, op: CmpOp) -> bool {
    match op {
        CmpOp::Lt => a < b,
        CmpOp::Le => a <= b,
        CmpOp::Gt => a > b,
        CmpOp::Ge => a >= b,
        _ => unreachable!(),
    }
}

fn eval_and(a: &Expr, b: &Expr, scope: &Scope) -> Result<EvalVal, ExprError> {
    let va = eval_expr(a, scope)?;
    match va.val {
        Some(Value::Bool(false)) => Ok(EvalVal {
            val: Some(Value::Bool(false)),
            sensitive: va.sensitive,
        }),
        Some(Value::Bool(true)) => {
            let vb = eval_expr(b, scope)?;
            let sensitive = va.sensitive || vb.sensitive;
            match vb.val {
                None => Ok(EvalVal {
                    val: None,
                    sensitive,
                }),
                Some(Value::Bool(_)) => Ok(EvalVal {
                    val: vb.val,
                    sensitive,
                }),
                Some(other) => err(format!(
                    "operator && requires boolean, got {}",
                    other.type_name()
                )),
            }
        }
        None => {
            let vb = eval_expr(b, scope)?;
            let sensitive = va.sensitive || vb.sensitive;
            match vb.val {
                Some(Value::Bool(false)) => Ok(EvalVal {
                    val: Some(Value::Bool(false)),
                    sensitive,
                }),
                Some(Value::Bool(true)) => Ok(EvalVal {
                    val: None,
                    sensitive,
                }),
                None => Ok(EvalVal {
                    val: None,
                    sensitive,
                }),
                Some(other) => err(format!(
                    "operator && requires boolean, got {}",
                    other.type_name()
                )),
            }
        }
        Some(other) => err(format!(
            "operator && requires boolean, got {}",
            other.type_name()
        )),
    }
}

fn eval_or(a: &Expr, b: &Expr, scope: &Scope) -> Result<EvalVal, ExprError> {
    let va = eval_expr(a, scope)?;
    match va.val {
        Some(Value::Bool(true)) => Ok(EvalVal {
            val: Some(Value::Bool(true)),
            sensitive: va.sensitive,
        }),
        Some(Value::Bool(false)) => {
            let vb = eval_expr(b, scope)?;
            let sensitive = va.sensitive || vb.sensitive;
            match vb.val {
                None => Ok(EvalVal {
                    val: None,
                    sensitive,
                }),
                Some(Value::Bool(_)) => Ok(EvalVal {
                    val: vb.val,
                    sensitive,
                }),
                Some(other) => err(format!(
                    "operator || requires boolean, got {}",
                    other.type_name()
                )),
            }
        }
        None => {
            let vb = eval_expr(b, scope)?;
            let sensitive = va.sensitive || vb.sensitive;
            match vb.val {
                Some(Value::Bool(true)) => Ok(EvalVal {
                    val: Some(Value::Bool(true)),
                    sensitive,
                }),
                Some(Value::Bool(false)) => Ok(EvalVal {
                    val: None,
                    sensitive,
                }),
                None => Ok(EvalVal {
                    val: None,
                    sensitive,
                }),
                Some(other) => err(format!(
                    "operator || requires boolean, got {}",
                    other.type_name()
                )),
            }
        }
        Some(other) => err(format!(
            "operator || requires boolean, got {}",
            other.type_name()
        )),
    }
}

// ---------------------------------------------------------------------------
// Interpolation
// ---------------------------------------------------------------------------

enum Segment {
    Literal(String),
    Expr(Expr),
}

/// Evaluate a string that may contain `{{ ... }}` interpolation tokens.
/// A string consisting solely of one interpolation retains the expression type.
pub fn eval_interpolated(s: &str, scope: &Scope) -> Result<EvalVal, ExprError> {
    let segments = split_interpolation(s)?;
    if segments.len() == 1 {
        if let Segment::Expr(e) = &segments[0] {
            return eval_expr(e, scope);
        }
    }
    let mut out = String::new();
    let mut sensitive = false;
    for seg in &segments {
        match seg {
            Segment::Literal(l) => out.push_str(l),
            Segment::Expr(e) => {
                let v = eval_expr(e, scope)?;
                sensitive = sensitive || v.sensitive;
                match v.val {
                    None => {
                        return Ok(EvalVal {
                            val: None,
                            sensitive,
                        })
                    }
                    Some(val) => match val.canonical_scalar_string() {
                        Some(sv) => out.push_str(&sv),
                        None => {
                            return err(format!(
                                "interpolated value must be a scalar, got {}",
                                val.type_name()
                            ))
                        }
                    },
                }
            }
        }
    }
    Ok(EvalVal {
        val: Some(Value::Str(out)),
        sensitive,
    })
}

fn split_interpolation(s: &str) -> Result<Vec<Segment>, ExprError> {
    let chars: Vec<char> = s.chars().collect();
    let mut segments = Vec::new();
    let mut lit = String::new();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '\\' && i + 2 < chars.len() && chars[i + 1] == '{' && chars[i + 2] == '{' {
            lit.push('{');
            lit.push('{');
            i += 3;
            continue;
        }
        if chars[i] == '{' && i + 1 < chars.len() && chars[i + 1] == '{' {
            if !lit.is_empty() {
                segments.push(Segment::Literal(std::mem::take(&mut lit)));
            }
            let start = i + 2;
            let end = find_close(&chars, start)
                .ok_or_else(|| ExprError("unterminated interpolation {{ ... }}".into()))?;
            let inner: String = chars[start..end].iter().collect();
            let expr = parse_expr(&inner)?;
            segments.push(Segment::Expr(expr));
            i = end + 2;
            continue;
        }
        lit.push(chars[i]);
        i += 1;
    }
    if !lit.is_empty() {
        segments.push(Segment::Literal(lit));
    }
    if segments.is_empty() {
        segments.push(Segment::Literal(String::new()));
    }
    Ok(segments)
}

fn find_close(chars: &[char], start: usize) -> Option<usize> {
    let mut i = start;
    let mut quote: Option<char> = None;
    while i < chars.len() {
        let c = chars[i];
        match quote {
            Some(q) => {
                if c == '\\' {
                    i += 2;
                    continue;
                }
                if c == q {
                    quote = None;
                }
            }
            None => {
                if c == '"' || c == '\'' {
                    quote = Some(c);
                } else if c == '}' && i + 1 < chars.len() && chars[i + 1] == '}' {
                    return Some(i);
                }
            }
        }
        i += 1;
    }
    None
}

/// Recursively evaluate interpolation over a nested value.
pub fn eval_value_interpolated(v: &Value, scope: &Scope) -> Result<EvalVal, ExprError> {
    match v {
        Value::Str(s) => eval_interpolated(s, scope),
        Value::Null => Ok(EvalVal::known(Value::Null)),
        Value::Bool(_) | Value::Int(_) | Value::Float(_) => Ok(EvalVal::known(v.clone())),
        Value::List(items) => {
            let mut out = Vec::with_capacity(items.len());
            let mut sensitive = false;
            for item in items {
                let ev = eval_value_interpolated(item, scope)?;
                sensitive = sensitive || ev.sensitive;
                match ev.val {
                    Some(val) => out.push(val),
                    None => {
                        return Ok(EvalVal {
                            val: None,
                            sensitive,
                        })
                    }
                }
            }
            Ok(EvalVal {
                val: Some(Value::List(out)),
                sensitive,
            })
        }
        Value::Map(m) => {
            let mut out = BTreeMap::new();
            let mut sensitive = false;
            for (k, item) in m {
                let ev = eval_value_interpolated(item, scope)?;
                sensitive = sensitive || ev.sensitive;
                match ev.val {
                    Some(val) => {
                        out.insert(k.clone(), val);
                    }
                    None => {
                        return Ok(EvalVal {
                            val: None,
                            sensitive,
                        })
                    }
                }
            }
            Ok(EvalVal {
                val: Some(Value::Map(out)),
                sensitive,
            })
        }
    }
}

/// Evaluate a `when`/`changed_when` expression that must produce a boolean or Unknown.
pub fn eval_boolean(e: &Expr, scope: &Scope) -> Result<EvalVal, ExprError> {
    let v = eval_expr(e, scope)?;
    match &v.val {
        None => Ok(v),
        Some(Value::Bool(_)) => Ok(v),
        Some(other) => err(format!(
            "boolean expression required, got {}",
            other.type_name()
        )),
    }
}

/// Collect the register names referenced by an expression. Used to validate the
/// direct dependency requirement (DESIGN §10.5).
pub fn collect_register_refs(
    e: &Expr,
    out: &mut std::collections::BTreeSet<String>,
    names: &mut std::collections::BTreeSet<String>,
) {
    match e {
        Expr::Or(a, b) | Expr::And(a, b) | Expr::Cmp(a, _, b) => {
            collect_register_refs(a, out, names);
            collect_register_refs(b, out, names);
        }
        Expr::Not(a) => collect_register_refs(a, out, names),
        Expr::Register(name, _) => {
            out.insert(name.clone());
        }
        Expr::Var(name) => {
            names.insert(name.clone());
        }
        Expr::ResultField(name) => {
            names.insert(name.clone());
        }
        Expr::Item => {}
        Expr::Fact(_)
        | Expr::Str(_)
        | Expr::Int(_)
        | Expr::Float(_)
        | Expr::Bool(_)
        | Expr::Null
        | Expr::TemplateVar(_) => {}
    }
}

/// Whether an expression text contains any interpolation token.
pub fn has_interpolation(s: &str) -> bool {
    let chars: Vec<char> = s.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '\\' && i + 2 < chars.len() && chars[i + 1] == '{' && chars[i + 2] == '{' {
            i += 3;
            continue;
        }
        if chars[i] == '{' && i + 1 < chars.len() && chars[i + 1] == '{' {
            return true;
        }
        i += 1;
    }
    false
}

pub fn format_value_plain(v: &Value) -> String {
    match v {
        Value::Str(s) => s.clone(),
        Value::Int(i) => i.to_string(),
        Value::Float(f) => format_float(*f),
        Value::Bool(b) => b.to_string(),
        Value::Null => "null".to_string(),
        _ => format!("{}", v),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope_with(vars: &BTreeMap<String, EvalVal>) -> Scope<'_> {
        Scope {
            vars: Some(vars),
            facts: None,
            registers: None,
            item: None,
            result: None,
            template: None,
        }
    }

    fn ev(src: &str) -> EvalVal {
        let vars = BTreeMap::new();
        let s = scope_with(&vars);
        eval_expr(&parse_expr(src).unwrap(), &s).unwrap()
    }

    fn evb(src: &str) -> Option<bool> {
        ev(src).val.and_then(|v| v.as_bool())
    }

    #[test]
    fn numeric_comparison() {
        assert_eq!(evb("1 < 2"), Some(true));
        assert_eq!(evb("2 <= 2"), Some(true));
        assert_eq!(evb("1 == 1.0"), Some(true));
        assert_eq!(evb("1 != 2"), Some(true));
    }

    #[test]
    fn string_comparison() {
        assert_eq!(evb("\"a\" < \"b\""), Some(true));
        assert_eq!(evb("\"a\" == \"a\""), Some(true));
    }

    #[test]
    fn boolean_ops() {
        assert_eq!(evb("true && false"), Some(false));
        assert_eq!(evb("true || false"), Some(true));
        assert_eq!(evb("!false"), Some(true));
    }

    #[test]
    fn ordering_boolean_errors() {
        assert!(eval_expr(
            &parse_expr("true < false").unwrap(),
            &scope_with(&BTreeMap::new())
        )
        .is_err());
    }

    #[test]
    fn short_circuit_avoids_undefined() {
        // false && undefined => false, no error
        assert_eq!(evb("false && vars.nope"), Some(false));
        assert_eq!(evb("true || vars.nope"), Some(true));
    }

    #[test]
    fn undefined_is_error_when_evaluated() {
        assert!(eval_expr(
            &parse_expr("vars.nope").unwrap(),
            &scope_with(&BTreeMap::new())
        )
        .is_err());
    }

    #[test]
    fn unknown_table() {
        let mut vars = BTreeMap::new();
        vars.insert("u".to_string(), EvalVal::unknown());
        let s = Scope {
            vars: Some(&vars),
            facts: None,
            registers: None,
            item: None,
            result: None,
            template: None,
        };

        fn run(src: &str, s: &Scope) -> Option<bool> {
            let e = parse_expr(src).unwrap();
            eval_boolean(&e, s).unwrap().val.and_then(|v| v.as_bool())
        }

        // false && Unknown => false
        assert_eq!(run("false && vars.u", &s), Some(false));
        // Unknown && false => false
        assert_eq!(run("vars.u && false", &s), Some(false));
        // true && Unknown => Unknown
        assert_eq!(run("true && vars.u", &s), None);
        // Unknown && true => Unknown
        assert_eq!(run("vars.u && true", &s), None);
        // true || Unknown => true
        assert_eq!(run("true || vars.u", &s), Some(true));
        // Unknown || true => true
        assert_eq!(run("vars.u || true", &s), Some(true));
        // false || Unknown => Unknown
        assert_eq!(run("false || vars.u", &s), None);
        // Unknown || false => Unknown
        assert_eq!(run("vars.u || false", &s), None);
        // !Unknown => Unknown
        assert_eq!(run("!vars.u", &s), None);
        // comparison with Unknown => Unknown
        assert_eq!(run("vars.u == 1", &s), None);
    }

    #[test]
    fn interpolation_type_retention() {
        let mut vars = BTreeMap::new();
        vars.insert("n".to_string(), EvalVal::known(Value::Int(5)));
        let s = Scope {
            vars: Some(&vars),
            facts: None,
            registers: None,
            item: None,
            result: None,
            template: None,
        };
        let v = eval_interpolated("{{ vars.n }}", &s).unwrap();
        assert_eq!(v.val, Some(Value::Int(5)));
        let v = eval_interpolated("x={{ vars.n }}", &s).unwrap();
        assert_eq!(v.val, Some(Value::Str("x=5".into())));
    }

    #[test]
    fn escaped_interpolation() {
        let vars = BTreeMap::new();
        let s = scope_with(&vars);
        let v = eval_interpolated("\\{{not an expr}}", &s).unwrap();
        assert_eq!(v.val, Some(Value::Str("{{not an expr}}".into())));
    }

    #[test]
    fn sensitive_propagation() {
        let mut vars = BTreeMap::new();
        vars.insert(
            "secret".to_string(),
            EvalVal::known_sensitive(Value::Str("hunter2".into())),
        );
        let s = Scope {
            vars: Some(&vars),
            facts: None,
            registers: None,
            item: None,
            result: None,
            template: None,
        };
        let v = eval_interpolated("pw={{ vars.secret }}", &s).unwrap();
        assert!(v.sensitive);
    }

    #[test]
    fn error_category_redacts_raw_values() {
        let e = parse_expr("987654321098765.43.21").unwrap_err();
        assert_eq!(e.category(), "invalid numeric literal");
        assert!(!e.category().contains("987654"));
        let e = parse_expr("R8_TEXT_SENTINEL_m4n5").unwrap_err();
        assert_eq!(e.category(), "unqualified reference");
        assert!(!e.category().contains("R8_TEXT"));
    }
}
