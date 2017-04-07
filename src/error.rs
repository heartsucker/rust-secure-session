//! Error types and utilities

/// Error types for session management operations
#[derive(Debug, Eq, PartialEq, Clone)]
pub enum SessionError {
    /// Error produced when a session fails to validate. This typically implies intentional
    /// client-side tampering.
    ValidationError,

    /// There was an internal error that prevented the session from being read or written.
    InternalError,
}

/// Error for invalid session configurations.
#[derive(Debug, Eq, PartialEq, Clone)]
pub enum SessionConfigError {
    /// An unknown error occurred.
    Undefined,
}
