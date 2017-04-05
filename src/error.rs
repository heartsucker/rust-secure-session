//! Error types and utilities

/// Error types for session management operations
#[derive(Debug, Eq, PartialEq, Clone)]
pub enum SessionError {
    /// Error produced when validation of a session fails to validate. This typically implies
    /// inentional client-side tampering.
    ValidationError,

    /// There was an internal error that prevented the session from being read or written.
    InternalError,
}
