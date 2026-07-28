//! Tiny error helpers — most error display comes from the SDK directly.

use std::fmt::Display;

pub fn short<E: Display>(e: &E) -> String {
    let s = format!("{}", e);
    if s.len() > 200 {
        format!("{}…", &s[..200])
    } else {
        s
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
