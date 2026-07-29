/// A UTF-8-safe bounded text value.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
/// mecmcp-compat: type mecmcp_server::BoundedText https://github.com/fastrevmd-lab/mecmcp/issues/101
pub(crate) struct BoundedText {
    /// Prefix ending on a UTF-8 character boundary.
    pub(crate) text: String,
    /// Whether bytes were omitted.
    pub(crate) truncated: bool,
    /// Original UTF-8 byte length.
    pub(crate) original_bytes: usize,
    /// Number of bytes omitted from the returned prefix.
    pub(crate) omitted_bytes: usize,
}

/// Bound text to at most `max_bytes` without splitting a UTF-8 code point.
#[must_use]
/// mecmcp-compat: function mecmcp_server::bounded_text https://github.com/fastrevmd-lab/mecmcp/issues/124
pub(crate) fn bounded_text(input: &str, max_bytes: usize) -> BoundedText {
    let original_bytes = input.len();
    if original_bytes <= max_bytes {
        return BoundedText {
            text: input.to_owned(),
            truncated: false,
            original_bytes,
            omitted_bytes: 0,
        };
    }
    let mut end = max_bytes.min(original_bytes);
    while end > 0 && !input.is_char_boundary(end) {
        end -= 1;
    }
    BoundedText {
        text: input[..end].to_owned(),
        truncated: true,
        original_bytes,
        omitted_bytes: original_bytes - end,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_text_never_splits_utf8() {
        let bounded = bounded_text("abé", 3);
        assert_eq!(bounded.text, "ab");
        assert!(bounded.truncated);
        assert_eq!(bounded.original_bytes, 4);
        assert_eq!(bounded.omitted_bytes, 2);
    }
}
