//! I/O error context retaining the original kernel error.
use std::{fmt, io};
pub(super) fn invalid(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

pub(super) fn context(error: io::Error, what: impl fmt::Display) -> io::Error {
    io::Error::new(
        error.kind(),
        OperationError {
            operation: what.to_string(),
            source: error,
        },
    )
}

#[derive(Debug)]
struct OperationError {
    operation: String,
    source: io::Error,
}

impl fmt::Display for OperationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.operation, self.source)
    }
}

impl std::error::Error for OperationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}
