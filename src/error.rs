//! Tiny error helpers — most error display comes from the SDK directly.

use std::fmt::Display;

pub fn short<E: Display>(e: &E) -> String {
    let s = format!("{}", e);
    // Truncate on a char boundary — byte-slicing `&s[..200]` panics if byte 200
    // splits a multibyte UTF-8 sequence (e.g. non-ASCII resource names).
    match s.char_indices().nth(200) {
        Some((idx, _)) => format!("{}…", &s[..idx]),
        None => s,
    }
}

/// Returns true when the error string looks like an authorization failure
/// (the expected outcome when a probe targets a denied action).
pub fn is_access_denied(s: &str) -> bool {
    s.contains("AccessDenied")
        || s.contains("UnauthorizedOperation")
        || s.contains("not authorized")
        || s.contains("AuthFailure")
        || s.contains("Forbidden")
}
