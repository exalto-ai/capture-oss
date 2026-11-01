use std::ops::Range;

use pest::{Parser, iterators::Pair as PestPair};

use super::types::{self, JsonValue, KeyValue};
use crate::{ParseError, Store, View, json::Document};

#[derive(pest_derive::Parser)]
#[grammar = "json/json.pest"]
struct JsonParser;

/// Maximum accepted object/array nesting depth.
///
/// LOCAL PATCH (see vendor/tlsn-utils/README.md): the `value`/`object`/`array`
/// grammar rules and the `JsonValue::from_pair` conversion recurse once per
/// nesting level, so deeply nested input could overflow the thread stack just
/// like escape-dense strings did before the grammar was made iterative. This
/// bound keeps parser stack usage constant and input-independent. It matches
/// `serde_json`'s default recursion limit; real LLM API payloads nest an
/// order of magnitude shallower.
pub const MAX_NESTING_DEPTH: usize = 128;

/// Returns the maximum object/array nesting depth of `data`, ignoring brackets
/// inside string literals.
///
/// This is an iterative string-aware scan, so it never rejects input the
/// grammar would accept below the depth limit: inside a string, the byte
/// following `\` is always skipped (covering `\"`, `\\`, and `\uXXXX`, since
/// hex digits are never quote, backslash, or bracket bytes). Byte-wise
/// scanning is safe because every structural character is ASCII and therefore
/// cannot appear inside a multi-byte UTF-8 sequence.
///
/// Malformed input (unbalanced brackets, unterminated strings) is not
/// diagnosed here; the pest parser reports it exactly as before.
fn nesting_depth(data: &str) -> usize {
    let mut depth = 0usize;
    let mut max_depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for &byte in data.as_bytes() {
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
            continue;
        }
        match byte {
            b'"' => in_string = true,
            b'{' | b'[' => {
                depth += 1;
                max_depth = max_depth.max(depth);
            }
            b'}' | b']' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    max_depth
}

/// Parse a JSON value.
///
/// # Example
///
/// ```
/// use spansy::json::parse;
///
/// // Parse borrowed
/// let value = parse(b"{\"foo\": 42}").unwrap();
/// assert_eq!(value.get("foo").unwrap(), "42");
/// ```
pub fn parse<S: Store>(src: impl Into<View<S>>) -> Result<Document<S>, ParseError> {
    let view: View<S, str> = src.into().try_into()?;
    let data = view.as_str();

    let depth = nesting_depth(&data);
    if depth > MAX_NESTING_DEPTH {
        return Err(ParseError(format!(
            "JSON nesting depth {depth} exceeds the maximum of {MAX_NESTING_DEPTH}"
        )));
    }

    let value = JsonParser::parse(Rule::json, &data)
        .map_err(ParseError::from_pest)?
        .next()
        .ok_or_else(|| ParseError("no json value is present in source".to_string()))?;

    let root = JsonValue::from_pair(&view, &data, value);

    Ok(Document { view, root })
}

/// Helper to get the range of a string within the data.
fn get_range(data: &str, s: &str) -> Range<usize> {
    let start = s.as_ptr() as usize - data.as_ptr() as usize;
    start..start + s.len()
}

impl<S: Store> JsonValue<S> {
    fn from_pair(view: &View<S, str>, data: &str, pair: PestPair<'_, Rule>) -> Self {
        match pair.as_rule() {
            Rule::object => Self::Object(types::Object::from_pair(view, data, pair)),
            Rule::array => Self::Array(types::Array::from_pair(view, data, pair)),
            Rule::string => Self::String(types::String::from_pair(view, data, pair)),
            Rule::number => Self::Number(types::Number::from_pair(view, data, pair)),
            Rule::bool => Self::Bool(types::Bool::from_pair(view, data, pair)),
            Rule::null => Self::Null(types::Null::from_pair(view, data, pair)),
            rule => unreachable!("unexpected matched rule: {:?}", rule),
        }
    }
}

impl<S: Store> types::JsonKey<S> {
    fn from_pair(view: &View<S, str>, data: &str, pair: PestPair<'_, Rule>) -> Self {
        assert!(matches!(pair.as_rule(), Rule::string));
        let range = get_range(data, pair.as_str());
        Self {
            view: view.select(range).expect("range should be valid"),
        }
    }
}

impl<S: Store> types::Number<S> {
    fn from_pair(view: &View<S, str>, data: &str, pair: PestPair<'_, Rule>) -> Self {
        assert!(matches!(pair.as_rule(), Rule::number));
        let range = get_range(data, pair.as_str());
        Self {
            view: view.select(range).expect("range should be valid"),
        }
    }
}

impl<S: Store> types::Bool<S> {
    fn from_pair(view: &View<S, str>, data: &str, pair: PestPair<'_, Rule>) -> Self {
        assert!(matches!(pair.as_rule(), Rule::bool));
        let range = get_range(data, pair.as_str());
        Self {
            view: view.select(range).expect("range should be valid"),
        }
    }
}

impl<S: Store> types::Null<S> {
    fn from_pair(view: &View<S, str>, data: &str, pair: PestPair<'_, Rule>) -> Self {
        assert!(matches!(pair.as_rule(), Rule::null));
        let range = get_range(data, pair.as_str());
        Self {
            view: view.select(range).expect("range should be valid"),
        }
    }
}

impl<S: Store> types::String<S> {
    fn from_pair(view: &View<S, str>, data: &str, pair: PestPair<'_, Rule>) -> Self {
        assert!(matches!(pair.as_rule(), Rule::string));
        let range = get_range(data, pair.as_str());
        Self {
            view: view.select(range).expect("range should be valid"),
        }
    }
}

impl<S: Store> KeyValue<S> {
    fn from_pair(view: &View<S, str>, data: &str, pair: PestPair<'_, Rule>) -> Self {
        assert!(matches!(pair.as_rule(), Rule::pair));

        let range = get_range(data, pair.as_str());

        let mut pairs = pair.into_inner();

        let key = pairs.next().expect("key should be present");
        let value = pairs.next().expect("value should be present");

        Self {
            view: view.select(range).expect("range should be valid"),
            key: types::JsonKey::from_pair(view, data, key),
            value: JsonValue::from_pair(view, data, value),
        }
    }
}

impl<S: Store> types::Object<S> {
    fn from_pair(view: &View<S, str>, data: &str, pair: PestPair<'_, Rule>) -> Self {
        assert!(matches!(pair.as_rule(), Rule::object));

        let range = get_range(data, pair.as_str());

        Self {
            view: view.select(range).expect("range should be valid"),
            elems: pair
                .into_inner()
                .map(|pair| KeyValue::from_pair(view, data, pair))
                .collect(),
        }
    }
}

impl<S: Store> types::Array<S> {
    fn from_pair(view: &View<S, str>, data: &str, pair: PestPair<'_, Rule>) -> Self {
        assert!(matches!(pair.as_rule(), Rule::array));

        let range = get_range(data, pair.as_str());

        Self {
            view: view.select(range).expect("range should be valid"),
            elems: pair
                .into_inner()
                .map(|pair| JsonValue::from_pair(view, data, pair))
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_json_spanner() {
        let src =
            br#"{"foo": "bar", "baz": 123, "quux": { "a": "b", "c": "d" }, "arr": [1, 2, 3]}"#;

        let value = parse(src).unwrap();

        assert_eq!(value.get("foo").unwrap(), "bar");
        assert_eq!(value.get("baz").unwrap(), "123");
        assert_eq!(value.get("quux.a").unwrap(), "b");
        assert_eq!(value.get("arr").unwrap(), "[1, 2, 3]");
    }

    #[test]
    fn test_json_borrowed() {
        let src: &[u8] = br#"{"foo": "bar"}"#;

        let value = parse(src).unwrap();

        assert_eq!(value.get("foo").unwrap(), "bar");
        assert!(value.view().indices().len_ranges() <= 1);
    }

    #[test]
    fn test_ok_leading_whitespace() {
        let src = b" {\"foo\": \"bar\"}";
        assert!(parse(src).is_ok());
    }

    #[test]
    fn test_ok_trailing_whitespace() {
        let src = b"{\"foo\": \"bar\"} ";
        assert!(parse(src).is_ok());
    }
    #[test]
    fn test_err_leading_characters() {
        let src = b"{}{\"foo\": \"bar\"}";
        assert!(parse(src).is_err());
    }

    #[test]
    fn test_err_trailing_characters() {
        let src = b"{\"foo\": \"bar\"}_";
        assert!(parse(src).is_err());
    }
    #[test]
    fn test_err_missing_comma() {
        // Missing comma between object pairs
        let src = b"{\"foo\": \"bar\" \"baz\": \"buzz\"}";
        assert!(parse(src).is_err());

        // Missing comma between array elements
        let src = b"[1 2 3]";
        assert!(parse(src).is_err());
    }

    #[test]
    fn test_err_trailing_comma_not_allowed() {
        // Trailing comma in object is invalid JSON
        let src = b"{\"foo\": \"bar\",}";
        assert!(parse(src).is_err());

        // Trailing comma in array is invalid JSON
        let src = b"[1, 2, 3,]";
        assert!(parse(src).is_err());
    }

    #[test]
    fn test_unicode_strings() {
        let src = r#"{"key": "日本語", "emoji": "🎉"}"#.as_bytes();
        let value = parse(src).unwrap();
        assert_eq!(value.get("key").unwrap(), "日本語");
        assert_eq!(value.get("emoji").unwrap(), "🎉");
    }

    #[test]
    fn test_escaped_characters() {
        let src = br#"{"a": "line1\nline2", "b": "tab\there", "c": "quote\"here"}"#;
        let value = parse(src).unwrap();
        // Spans contain raw content without quotes
        assert_eq!(
            value.get("a").unwrap().view().as_str().as_ref(),
            r#"line1\nline2"#
        );
        assert_eq!(
            value.get("b").unwrap().view().as_str().as_ref(),
            r#"tab\there"#
        );
        assert_eq!(
            value.get("c").unwrap().view().as_str().as_ref(),
            r#"quote\"here"#
        );
    }

    #[test]
    fn test_numbers() {
        let src = br#"{"neg": -42, "float": 3.14, "exp": 1e10, "neg_exp": 2.5e-3}"#;
        let value = parse(src).unwrap();
        assert_eq!(value.get("neg").unwrap(), "-42");
        assert_eq!(value.get("float").unwrap(), "3.14");
        assert_eq!(value.get("exp").unwrap(), "1e10");
        assert_eq!(value.get("neg_exp").unwrap(), "2.5e-3");
    }

    #[test]
    fn test_whitespace_variations() {
        let src = b"{\n\t\"a\"\t:\n1\n,\t\"b\" : 2\n}";
        let value = parse(src).unwrap();
        assert_eq!(value.get("a").unwrap(), "1");
        assert_eq!(value.get("b").unwrap(), "2");
    }

    #[test]
    fn test_empty_structures() {
        let src = br#"{"obj": {}, "arr": [], "nested": {"empty": {}}}"#;
        let value = parse(src).unwrap();
        assert_eq!(value.get("obj").unwrap(), "{}");
        assert_eq!(value.get("arr").unwrap(), "[]");
        assert_eq!(value.get("nested.empty").unwrap(), "{}");
    }

    #[test]
    fn test_deeply_nested() {
        let src = br#"{"a": {"b": {"c": {"d": {"e": {"f": 42}}}}}}"#;
        let value = parse(src).unwrap();
        assert_eq!(value.get("a.b.c.d.e.f").unwrap(), "42");
    }

    // LOCAL PATCH tests (see vendor/tlsn-utils/README.md): the iterative
    // string grammar and the nesting-depth bound.

    #[test]
    fn test_iterative_string_many_escapes() {
        // Thousands of escapes across every escape class. The recursive
        // `escape ~ string` grammar consumed one parser stack frame per
        // escape and overflowed the stack on escape-dense LLM prompts; the
        // iterative grammar parses this with constant stack usage.
        let mut content = std::string::String::new();
        for _ in 0..5000 {
            content.push_str("\\n\\\"\\\\ \\u00e9");
        }
        let src = format!("{{\"prompt\": \"{content}\"}}");
        let doc = parse(src.as_bytes()).unwrap();
        let prompt = doc.get("prompt").unwrap();
        // The string span covers exactly the raw escaped content (no quotes).
        assert_eq!(prompt.view().offset(), 12);
        assert_eq!(prompt.view().as_str().as_ref(), content.as_str());
    }

    #[test]
    fn test_long_unescaped_string() {
        let content = "lorem ipsum ".repeat(50_000);
        let src = format!("{{\"s\": \"{content}\"}}");
        let doc = parse(src.as_bytes()).unwrap();
        assert_eq!(doc.get("s").unwrap().view().len(), content.len());
    }

    #[test]
    fn test_string_span_offsets_unchanged() {
        // Disclosure depends on exact byte ranges; the iterative grammar must
        // produce the same spans as the recursive one.
        let src = br#"{"a": "x\ny", "b": "pq"}"#;
        let doc = parse(src.as_slice()).unwrap();
        let a = doc.get("a").unwrap();
        assert_eq!(a.view().offset(), 7);
        assert_eq!(a.view().as_str().as_ref(), r#"x\ny"#);
        let b = doc.get("b").unwrap();
        assert_eq!(b.view().offset(), 20);
        assert_eq!(b.view().as_str().as_ref(), "pq");
    }

    #[test]
    fn test_nesting_depth_boundary() {
        // Exactly the maximum depth parses.
        let open = "[".repeat(MAX_NESTING_DEPTH);
        let close = "]".repeat(MAX_NESTING_DEPTH);
        let src = format!("{open}42{close}");
        let doc = parse(src.as_bytes()).unwrap();
        let path = vec!["0"; MAX_NESTING_DEPTH].join(".");
        assert_eq!(doc.get(&path).unwrap(), "42");

        // One level beyond is a typed parse error, not a stack overflow.
        let open = "[".repeat(MAX_NESTING_DEPTH + 1);
        let close = "]".repeat(MAX_NESTING_DEPTH + 1);
        let src = format!("{open}42{close}");
        let err = parse(src.as_bytes()).unwrap_err();
        assert!(
            err.to_string().contains("nesting depth"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_nesting_depth_ignores_brackets_in_strings() {
        // Brackets inside string literals must not count toward the depth
        // limit, including brackets after escaped backslashes and quotes.
        let mut content = std::string::String::new();
        for _ in 0..500 {
            content.push_str("[{\\\"}]"); // JSON text for the characters [{"}]
            content.push_str("\\\\"); // escaped backslash
            content.push_str("[[");
        }
        let src = format!("{{\"s\": \"{content}\"}}");
        let doc = parse(src.as_bytes()).unwrap();
        assert_eq!(doc.get("s").unwrap().view().len(), content.len());
    }

    #[test]
    fn test_nesting_depth_mixed_containers() {
        // A mixed object/array document at the boundary still parses, and the
        // depth of a shallow document full of bracket-heavy strings is the
        // document's own depth.
        let mut src = std::string::String::new();
        for level in 0..MAX_NESTING_DEPTH {
            if level % 2 == 0 {
                src.push_str("{\"k\": ");
            } else {
                src.push('[');
            }
        }
        src.push('1');
        for level in (0..MAX_NESTING_DEPTH).rev() {
            if level % 2 == 0 {
                src.push('}');
            } else {
                src.push(']');
            }
        }
        assert!(parse(src.as_bytes()).is_ok());
    }

    #[test]
    fn test_array_access() {
        let src = br#"[1, [2, [3, [4, 5]]]]"#;
        let value = parse(src).unwrap();
        assert_eq!(value.get("0").unwrap(), "1");
        assert_eq!(value.get("1.0").unwrap(), "2");
        assert_eq!(value.get("1.1.0").unwrap(), "3");
        assert_eq!(value.get("1.1.1.0").unwrap(), "4");
        assert_eq!(value.get("1.1.1.1").unwrap(), "5");
    }

    #[test]
    fn test_booleans_and_null() {
        let src = br#"{"t": true, "f": false, "n": null}"#;
        let value = parse(src).unwrap();
        assert_eq!(value.get("t").unwrap(), "true");
        assert_eq!(value.get("f").unwrap(), "false");
        assert_eq!(value.get("n").unwrap(), "null");
    }

    #[test]
    fn test_non_contiguous_json() {
        use crate::http::{BodyContent, parse_response};

        // JSON split across two chunks: {"key": + "value"}
        let src = b"HTTP/1.1 200 OK\r\n\
            Transfer-Encoding: chunked\r\n\
            Content-Type: application/json\r\n\r\n\
            8\r\n{\"key\": \r\n\
            8\r\n\"value\"}\r\n\
            0\r\n\r\n";

        let res = parse_response(src).unwrap();
        let body = res.body.unwrap();

        // Body has 2 chunks
        assert_eq!(body.chunks.as_ref().unwrap().len(), 2);

        let BodyContent::Json(value) = body.content else {
            panic!("body should be json");
        };

        // Verify we can access parsed JSON correctly
        assert_eq!(value.get("key").unwrap(), "value");

        // Verify the full JSON view is non-contiguous (spans 2 chunks)
        let json_view = value.view();
        assert!(json_view.indices().len_ranges() > 1);
    }
}
