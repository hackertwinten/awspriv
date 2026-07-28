//! Error helpers.
//!
//! Enumeration control flow (probe fail-fast, simulate bail-out, the
//! confirmed-vs-unexpected split) keys off *why* a call failed. Prefer the
//! modeled error **code** (`ProvideErrorMetadata::code()`) over the free-form
//! Display string, so an SDK rewording of a message can't silently change
//! behavior. A string fallback covers transport-level errors that carry no
//! modeled code (timeouts, dispatch failures).

use std::fmt::Display;

use aws_sdk_iam::error::ProvideErrorMetadata;

/// Why a call failed, as far as enumeration cares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorClass {
    /// Authorization failure — the expected outcome of a probe with no access.
    AccessDenied,
    /// Rate limiting. NOT an absence of permission — must not be reported as
    /// "no access", and is a candidate for retry/inconclusive handling.
    Throttling,
    /// Anything else (transport error, unexpected service error).
    Other,
}

// Modeled error codes. IAM/STS use `*Exception` suffixes; EC2 and the older
// query-protocol services use bare codes like `UnauthorizedOperation`.
const ACCESS_DENIED_CODES: &[&str] = &[
    "AccessDenied",
    "AccessDeniedException",
    "UnauthorizedOperation",
    "AuthFailure",
    "Forbidden",
    "NotAuthorized",
    "MissingAuthenticationToken",
];

const THROTTLING_CODES: &[&str] = &[
    "Throttling",
    "ThrottlingException",
    "ThrottledException",
    "TooManyRequestsException",
    "RequestLimitExceeded",
    "RequestThrottled",
    "RequestThrottledException",
    "SlowDown",
];

/// Classify an SDK error from its modeled code, falling back to the message
/// only when no code is present (e.g. a connection timeout).
pub fn classify<E: ProvideErrorMetadata + Display>(err: &E) -> ErrorClass {
    if let Some(code) = err.code() {
        if ACCESS_DENIED_CODES.iter().any(|c| c.eq_ignore_ascii_case(code)) {
            return ErrorClass::AccessDenied;
        }
        if THROTTLING_CODES.iter().any(|c| c.eq_ignore_ascii_case(code)) {
            return ErrorClass::Throttling;
        }
        return ErrorClass::Other;
    }
    classify_str(&err.to_string())
}

/// Message-based fallback for errors without a modeled code.
pub fn classify_str(s: &str) -> ErrorClass {
    if looks_access_denied(s) {
        ErrorClass::AccessDenied
    } else if looks_throttling(s) {
        ErrorClass::Throttling
    } else {
        ErrorClass::Other
    }
}

fn looks_access_denied(s: &str) -> bool {
    s.contains("AccessDenied")
        || s.contains("UnauthorizedOperation")
        || s.contains("not authorized")
        || s.contains("AuthFailure")
        || s.contains("Forbidden")
}

fn looks_throttling(s: &str) -> bool {
    s.contains("Throttling")
        || s.contains("Throttled")
        || s.contains("RequestLimitExceeded")
        || s.contains("TooManyRequests")
        || s.contains("SlowDown")
}

pub fn short<E: Display>(e: &E) -> String {
    let s = format!("{}", e);
    // Truncate on a char boundary — byte-slicing `&s[..200]` panics if byte 200
    // splits a multibyte UTF-8 sequence (e.g. non-ASCII resource names).
    match s.char_indices().nth(200) {
        Some((idx, _)) => format!("{}…", &s[..idx]),
        None => s,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_access_denied_from_strings() {
        assert_eq!(classify_str("... AccessDenied: no"), ErrorClass::AccessDenied);
        assert_eq!(classify_str("UnauthorizedOperation"), ErrorClass::AccessDenied);
        assert_eq!(
            classify_str("User is not authorized to perform"),
            ErrorClass::AccessDenied
        );
    }

    #[test]
    fn classifies_throttling_from_strings() {
        assert_eq!(classify_str("ThrottlingException"), ErrorClass::Throttling);
        assert_eq!(classify_str("RequestLimitExceeded"), ErrorClass::Throttling);
        assert_eq!(classify_str("SlowDown: reduce rate"), ErrorClass::Throttling);
    }

    #[test]
    fn unknown_is_other() {
        assert_eq!(classify_str("ValidationError: bad input"), ErrorClass::Other);
        assert_eq!(classify_str("connection reset"), ErrorClass::Other);
    }

    #[test]
    fn throttling_is_not_access_denied() {
        // The crux of #3: a throttled key is not a key with no permissions.
        assert_ne!(classify_str("ThrottlingException"), ErrorClass::AccessDenied);
    }
}
