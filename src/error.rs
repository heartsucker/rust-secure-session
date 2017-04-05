#[derive(Debug, Eq, PartialEq, Clone)]
pub enum SessionError {
    ValidationError,
    InternalError,
}
