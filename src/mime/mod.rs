//! A small, order- and byte-preserving MIME model.
//!
//! The gateway needs to keep original header blocks and multipart
//! boundaries (§9.6), copy header fields verbatim (§11.8.2), and rebuild
//! messages deterministically, so it uses its own tree instead of a
//! decoding-oriented parser.

pub mod encoding;

use std::fmt;

pub use encoding::*;

/// One header field. `raw` holds the complete field (name, colon and the
/// possibly folded value) without the terminating line break.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderField {
    pub name: String,
    pub raw: Vec<u8>,
}

impl HeaderField {
    pub fn new(name: &str, value: &str) -> Self {
        Self {
            name: name.to_string(),
            raw: format!("{name}: {value}").into_bytes(),
        }
    }

    /// Unfolded, trimmed value.
    pub fn value(&self) -> String {
        let s = String::from_utf8_lossy(&self.raw);
        let v = s.split_once(':').map(|(_, v)| v).unwrap_or("");
        unfold(v).trim().to_string()
    }
}

fn unfold(v: &str) -> String {
    // Folding: CRLF followed by WSP becomes the WSP.
    v.chars().filter(|&c| c != '\r' && c != '\n').collect()
}

/// An ordered header block.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Header {
    pub fields: Vec<HeaderField>,
}

fn valid_field_name(name: &[u8]) -> bool {
    !name.is_empty() && name.iter().all(|&b| (33..=126).contains(&b) && b != b':')
}

/// Find the end of the header section: returns `(header_end, body_start)`.
fn split_header(data: &[u8]) -> (usize, usize) {
    if data.starts_with(b"\r\n") {
        return (0, 2);
    }
    if data.starts_with(b"\n") {
        return (0, 1);
    }
    let mut i = 0;
    while i < data.len() {
        if data[i] == b'\n' {
            if data[i + 1..].starts_with(b"\r\n") {
                return (i + 1, i + 3);
            }
            if data[i + 1..].starts_with(b"\n") {
                return (i + 1, i + 2);
            }
        }
        i += 1;
    }
    (data.len(), data.len())
}

impl Header {
    pub fn new() -> Self {
        Self::default()
    }

    /// Parse a header block. Returns `None` if a line is neither a field nor
    /// a continuation.
    pub fn parse(data: &[u8]) -> Option<Self> {
        let mut fields: Vec<HeaderField> = Vec::new();
        for line in split_lines(data) {
            if line.is_empty() {
                continue;
            }
            if line[0] == b' ' || line[0] == b'\t' {
                let last = fields.last_mut()?;
                last.raw.extend_from_slice(b"\r\n");
                last.raw.extend_from_slice(line);
                continue;
            }
            let colon = line.iter().position(|&b| b == b':')?;
            let name = line[..colon].trim_ascii_end();
            if !valid_field_name(name) {
                return None;
            }
            fields.push(HeaderField {
                name: String::from_utf8_lossy(name).to_string(),
                raw: line.to_vec(),
            });
        }
        Some(Self { fields })
    }

    pub fn get(&self, name: &str) -> Option<String> {
        self.fields
            .iter()
            .find(|f| f.name.eq_ignore_ascii_case(name))
            .map(HeaderField::value)
    }

    pub fn get_all(&self, name: &str) -> Vec<String> {
        self.fields
            .iter()
            .filter(|f| f.name.eq_ignore_ascii_case(name))
            .map(HeaderField::value)
            .collect()
    }

    pub fn contains(&self, name: &str) -> bool {
        self.fields
            .iter()
            .any(|f| f.name.eq_ignore_ascii_case(name))
    }

    /// Replace the first instance in place (removing any others), or append.
    pub fn set(&mut self, name: &str, value: &str) {
        let field = HeaderField::new(name, value);
        if let Some(pos) = self
            .fields
            .iter()
            .position(|f| f.name.eq_ignore_ascii_case(name))
        {
            self.fields[pos] = field;
            let mut i = pos + 1;
            while i < self.fields.len() {
                if self.fields[i].name.eq_ignore_ascii_case(name) {
                    self.fields.remove(i);
                } else {
                    i += 1;
                }
            }
        } else {
            self.fields.push(field);
        }
    }

    pub fn add(&mut self, name: &str, value: &str) {
        self.fields.push(HeaderField::new(name, value));
    }

    pub fn add_raw(&mut self, field: HeaderField) {
        self.fields.push(field);
    }

    pub fn remove(&mut self, name: &str) {
        self.fields.retain(|f| !f.name.eq_ignore_ascii_case(name));
    }

    /// Serialise with CRLF line endings (no terminating blank line).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for f in &self.fields {
            out.extend_from_slice(&normalize_crlf(&f.raw));
            out.extend_from_slice(b"\r\n");
        }
        out
    }

    pub fn content_type(&self) -> Option<ContentType> {
        self.get("Content-Type")
            .and_then(|v| ContentType::parse(&v))
    }
}

/// Split into lines without terminators (handles CRLF and LF).
fn split_lines(data: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut start = 0;
    for (i, &b) in data.iter().enumerate() {
        if b == b'\n' {
            let mut end = i;
            if end > start && data[end - 1] == b'\r' {
                end -= 1;
            }
            out.push(&data[start..end]);
            start = i + 1;
        }
    }
    if start < data.len() {
        out.push(&data[start..]);
    }
    out
}

/// A parsed `Content-Type` / `Content-Disposition` value.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ContentType {
    /// Lowercased value, e.g. `text/plain` or `attachment`.
    pub value: String,
    /// Parameters with lowercased names, in order.
    pub params: Vec<(String, String)>,
}

impl ContentType {
    pub fn new(value: &str) -> Self {
        Self {
            value: value.to_ascii_lowercase(),
            params: Vec::new(),
        }
    }

    /// Parse `value; k=v; k2="v 2"` with RFC 2231 continuations and
    /// extended values. Returns `None` for an empty or malformed value.
    pub fn parse(s: &str) -> Option<Self> {
        let tokens = split_params(s);
        let mut it = tokens.into_iter();
        let value = it.next()?.trim().to_ascii_lowercase();
        if value.is_empty() || value.contains(char::is_whitespace) {
            return None;
        }
        let mut raw: Vec<(String, String)> = Vec::new();
        for t in it {
            let t = t.trim();
            if t.is_empty() {
                continue;
            }
            let (k, v) = t.split_once('=')?;
            let k = k.trim().to_ascii_lowercase();
            let v = v.trim();
            let v = if v.starts_with('"') && v.ends_with('"') && v.len() >= 2 {
                unquote(&v[1..v.len() - 1])
            } else {
                v.to_string()
            };
            raw.push((k, v));
        }
        Some(Self {
            value,
            params: merge_rfc2231(raw),
        })
    }

    pub fn param(&self, name: &str) -> Option<&str> {
        self.params
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    pub fn set_param(&mut self, name: &str, value: &str) {
        let name = name.to_ascii_lowercase();
        if let Some(p) = self.params.iter_mut().find(|(k, _)| *k == name) {
            p.1 = value.to_string();
        } else {
            self.params.push((name, value.to_string()));
        }
    }

    pub fn remove_param(&mut self, name: &str) {
        self.params.retain(|(k, _)| !k.eq_ignore_ascii_case(name));
    }

    pub fn main_type(&self) -> &str {
        self.value.split('/').next().unwrap_or("")
    }

    pub fn sub_type(&self) -> &str {
        self.value.split_once('/').map(|(_, s)| s).unwrap_or("")
    }

    pub fn is_multipart(&self) -> bool {
        self.main_type() == "multipart"
    }
}

impl fmt::Display for ContentType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.value)?;
        for (k, v) in &self.params {
            if !v.is_empty()
                && v.chars()
                    .all(|c| c.is_ascii_alphanumeric() || "!#$&-^_.+".contains(c))
            {
                write!(f, "; {k}={v}")?;
            } else {
                write!(
                    f,
                    "; {k}=\"{}\"",
                    v.replace('\\', "\\\\").replace('"', "\\\"")
                )?;
            }
        }
        Ok(())
    }
}

fn unquote(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut esc = false;
    for c in s.chars() {
        if esc {
            out.push(c);
            esc = false;
        } else if c == '\\' {
            esc = true;
        } else {
            out.push(c);
        }
    }
    out
}

fn split_params(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_q = false;
    let mut esc = false;
    for c in s.chars() {
        if esc {
            cur.push(c);
            esc = false;
            continue;
        }
        match c {
            '\\' if in_q => {
                cur.push(c);
                esc = true;
            }
            '"' => {
                in_q = !in_q;
                cur.push(c);
            }
            ';' if !in_q => out.push(std::mem::take(&mut cur)),
            '\r' | '\n' => {}
            _ => cur.push(c),
        }
    }
    out.push(cur);
    out
}

fn pct_decode(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%'
            && i + 2 < b.len()
            && let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16)
        {
            out.push(v);
            i += 3;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    out
}

fn merge_rfc2231(raw: Vec<(String, String)>) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    let mut charset_of: Vec<(String, String)> = Vec::new();
    for (k, v) in raw {
        if let Some((base, rest)) = k.split_once('*') {
            let extended = rest.ends_with('*') || rest.is_empty();
            let mut piece = v.clone();
            if extended {
                // charset'lang'value on the first extended segment.
                let mut cs = charset_of
                    .iter()
                    .find(|(b, _)| b == base)
                    .map(|(_, c)| c.clone());
                if (rest.is_empty() || rest == "0*")
                    && let Some((charset, tail)) = v.split_once('\'')
                    && let Some((_, val)) = tail.split_once('\'')
                {
                    cs = Some(charset.to_string());
                    charset_of.push((base.to_string(), charset.to_string()));
                    piece = val.to_string();
                }
                let bytes = pct_decode(&piece);
                piece = cs
                    .as_deref()
                    .and_then(|c| decode_charset(&bytes, c))
                    .unwrap_or_else(|| decode_heuristic(&bytes));
            }
            if let Some(e) = out.iter_mut().find(|(b, _)| b == base) {
                e.1.push_str(&piece);
            } else {
                out.push((base.to_string(), piece));
            }
        } else if let Some(e) = out.iter_mut().find(|(b, _)| *b == k) {
            // Duplicate parameters are tolerated: the first wins.
            let _ = e;
        } else {
            out.push((k, v));
        }
    }
    out
}

/// A MIME entity.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Part {
    pub header: Header,
    /// Raw (transfer-encoded) body of a leaf part.
    pub body: Vec<u8>,
    pub children: Vec<Part>,
    pub boundary: Option<String>,
    pub preamble: Vec<u8>,
    pub epilogue: Vec<u8>,
}

impl Part {
    /// A leaf part.
    pub fn leaf(header: Header, body: Vec<u8>) -> Self {
        Self {
            header,
            body,
            ..Default::default()
        }
    }

    /// A multipart part with the given subtype and children.
    pub fn multipart(subtype: &str, boundary: String, children: Vec<Part>) -> Self {
        let mut header = Header::new();
        header.set(
            "Content-Type",
            &format!("multipart/{subtype}; boundary={boundary}"),
        );
        Self {
            header,
            body: Vec::new(),
            children,
            boundary: Some(boundary),
            ..Default::default()
        }
    }

    /// Parse a complete entity. Fails if the header section is invalid.
    pub fn parse(data: &[u8]) -> Option<Self> {
        Self::parse_depth(data, 0)
    }

    fn parse_depth(data: &[u8], depth: usize) -> Option<Self> {
        let (hend, bstart) = split_header(data);
        let header = Header::parse(&data[..hend])?;
        let body = &data[bstart.min(data.len())..];
        let ct = header.content_type();
        if let Some(ct) = &ct
            && ct.is_multipart()
            && depth < 64
            && let Some(b) = ct.param("boundary").map(str::to_string)
            && let Some((preamble, kids, epilogue)) = split_multipart(body, &b)
        {
            let mut children = Vec::new();
            for k in kids {
                children.push(Self::parse_depth(k, depth + 1).unwrap_or_else(|| Part {
                    body: k.to_vec(),
                    ..Default::default()
                }));
            }
            return Some(Self {
                header,
                body: Vec::new(),
                children,
                boundary: Some(b),
                preamble: preamble.to_vec(),
                epilogue: epilogue.to_vec(),
            });
        }
        Some(Self::leaf(header, body.to_vec()))
    }

    pub fn is_multipart(&self) -> bool {
        self.boundary.is_some()
    }

    /// Content-Type (defaults to `text/plain`).
    pub fn content_type(&self) -> ContentType {
        self.header
            .content_type()
            .unwrap_or_else(|| ContentType::new("text/plain"))
    }

    /// Content-Disposition, if present and parsable.
    pub fn disposition(&self) -> Option<ContentType> {
        self.header
            .get("Content-Disposition")
            .and_then(|v| ContentType::parse(&v))
    }

    /// Content-Transfer-Encoding, with RFC 2047 words decoded (§13.8 rule 2).
    pub fn cte(&self) -> String {
        self.header
            .get("Content-Transfer-Encoding")
            .map(|v| decode_rfc2047(&v).trim().to_ascii_lowercase())
            .unwrap_or_default()
    }

    /// Content-ID with angle brackets and spaces trimmed.
    pub fn content_id(&self) -> Option<String> {
        self.header
            .get("Content-Id")
            .map(|v| v.trim().trim_matches(['<', '>', ' ']).to_string())
            .filter(|v| !v.is_empty())
    }

    /// Transfer-decoded body.
    pub fn decoded_body(&self) -> Vec<u8> {
        decode_cte(&self.body, &self.cte())
    }

    /// Body decoded to text using the `charset` parameter.
    pub fn text(&self) -> String {
        let raw = self.decoded_body();
        match self.content_type().param("charset") {
            Some(cs) => decode_charset(&raw, cs).unwrap_or_else(|| decode_heuristic(&raw)),
            None => decode_heuristic(&raw),
        }
    }

    /// Replace the body with `data` encoded per `cte` and update headers.
    pub fn set_body(&mut self, data: &[u8], cte: &str) {
        match cte {
            "base64" => {
                self.body = crate::util::b64_wrapped(data).into_bytes();
                self.header.set("Content-Transfer-Encoding", "base64");
            }
            "quoted-printable" => {
                self.body = qp_encode(data).into_bytes();
                self.header
                    .set("Content-Transfer-Encoding", "quoted-printable");
            }
            _ => {
                self.body = data.to_vec();
                if cte.is_empty() {
                    self.header.remove("Content-Transfer-Encoding");
                } else {
                    self.header.set("Content-Transfer-Encoding", cte);
                }
            }
        }
    }

    /// All leaf parts in depth-first document order.
    pub fn leaves(&self) -> Vec<&Part> {
        let mut out = Vec::new();
        self.collect_leaves(&mut out);
        out
    }

    fn collect_leaves<'a>(&'a self, out: &mut Vec<&'a Part>) {
        if self.is_multipart() {
            for c in &self.children {
                c.collect_leaves(out);
            }
        } else {
            out.push(self);
        }
    }

    /// Mutable visit of every part (pre-order).
    pub fn visit_mut(&mut self, f: &mut dyn FnMut(&mut Part)) {
        f(self);
        for c in &mut self.children {
            c.visit_mut(f);
        }
    }

    /// Serialise with CRLF line endings.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.write(&mut out);
        out
    }

    fn write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.header.to_bytes());
        out.extend_from_slice(b"\r\n");
        match &self.boundary {
            Some(b) => {
                out.extend_from_slice(&self.preamble);
                for (i, c) in self.children.iter().enumerate() {
                    if i > 0 {
                        out.extend_from_slice(b"\r\n");
                    }
                    out.extend_from_slice(format!("--{b}\r\n").as_bytes());
                    c.write(out);
                }
                out.extend_from_slice(format!("\r\n--{b}--\r\n").as_bytes());
                out.extend_from_slice(&self.epilogue);
            }
            None => out.extend_from_slice(&self.body),
        }
    }
}

/// Split a multipart body into (preamble, children, epilogue).
type MultipartSplit<'a> = (&'a [u8], Vec<&'a [u8]>, &'a [u8]);

fn split_multipart<'a>(body: &'a [u8], boundary: &str) -> Option<MultipartSplit<'a>> {
    let delim = format!("--{boundary}");
    let d = delim.as_bytes();
    // Collect delimiter line positions: (line_start, line_end_after_newline, is_close).
    let mut marks = Vec::new();
    let mut pos = 0;
    while pos <= body.len() {
        let line_end = body[pos..]
            .iter()
            .position(|&b| b == b'\n')
            .map(|i| pos + i + 1)
            .unwrap_or(body.len());
        let line = &body[pos..line_end];
        if line.starts_with(d) {
            let rest = line[d.len()..].trim_ascii_end();
            if rest.is_empty() {
                marks.push((pos, line_end, false));
            } else if rest.starts_with(b"--") {
                marks.push((pos, line_end, true));
                break;
            }
        }
        if line_end == body.len() {
            break;
        }
        pos = line_end;
    }
    if marks.is_empty() {
        return None;
    }
    let strip_nl = |end: usize| -> usize {
        if end >= 2 && &body[end - 2..end] == b"\r\n" {
            end - 2
        } else if end >= 1 && body[end - 1] == b'\n' {
            end - 1
        } else {
            end
        }
    };
    let preamble = &body[..marks[0].0];
    let mut kids = Vec::new();
    for w in marks.windows(2) {
        let (_, start, close) = w[0];
        if close {
            break;
        }
        let end = strip_nl(w[1].0).max(start);
        kids.push(&body[start..end]);
    }
    let last = *marks.last()?;
    let epilogue = if last.2 {
        &body[last.1..]
    } else {
        // Unterminated: the remainder is the last child.
        kids.push(&body[last.1..]);
        &body[body.len()..]
    };
    Some((preamble, kids, epilogue))
}

/// Split content into (header, body) at the first empty line. Returns `None`
/// if the header section is not a valid header (§11.8.3 case B).
pub fn split_entity(data: &[u8]) -> Option<(Header, Vec<u8>)> {
    let (hend, bstart) = split_header(data);
    if hend == data.len() && bstart == data.len() {
        return None;
    }
    let h = Header::parse(&data[..hend])?;
    if h.fields.is_empty() {
        return None;
    }
    Some((h, data[bstart.min(data.len())..].to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const MSG: &[u8] = b"From: a@b.c\r\nSubject: hi\r\n there\r\nContent-Type: multipart/mixed; boundary=\"XX\"\r\n\r\npre\r\n--XX\r\nContent-Type: text/plain\r\n\r\nhello\r\n--XX\r\nContent-Type: application/octet-stream\r\nContent-Transfer-Encoding: base64\r\n\r\naGk=\r\n--XX--\r\n";

    #[test]
    fn parse_and_roundtrip() {
        let p = Part::parse(MSG).unwrap();
        assert_eq!(p.header.get("subject").unwrap(), "hi there");
        assert_eq!(p.children.len(), 2);
        assert_eq!(p.children[0].body, b"hello");
        assert_eq!(p.children[1].decoded_body(), b"hi");
        assert_eq!(p.to_bytes(), MSG);
    }

    #[test]
    fn content_type_params() {
        let ct = ContentType::parse("Text/Plain; charset=\"utf-8\"; name*0=\"a\"; name*1=\"b\"")
            .unwrap();
        assert_eq!(ct.value, "text/plain");
        assert_eq!(ct.param("charset"), Some("utf-8"));
        assert_eq!(ct.param("name"), Some("ab"));
        let ct = ContentType::parse("application/x; filename*=utf-8''%e2%98%95.gif").unwrap();
        assert_eq!(ct.param("filename"), Some("☕.gif"));
    }

    #[test]
    fn header_set_preserves_position() {
        let mut h = Header::parse(b"A: 1\r\nB: 2\r\nC: 3").unwrap();
        h.set("b", "x");
        assert_eq!(h.to_bytes(), b"A: 1\r\nb: x\r\nC: 3\r\n");
    }

    #[test]
    fn invalid_header() {
        assert!(split_entity(b"just some text\r\n\r\nbody").is_none());
        assert!(split_entity(b"X-A: b\r\n\r\nbody").is_some());
    }
}
