use std::fmt;

/// Why a GTP-U message, or an inner IPv4 packet, cannot be decoded or encoded.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The input ends inside the named structure.
    Truncated(&'static str),
    /// A length of the named structure is inconsistent with its content or
    /// with the input.
    InvalidLength(&'static str),
    /// The first octet is not that of a GTPv1-U message: version 1,
    /// protocol type GTP (not GTP').
    UnsupportedVersion(u8),
    /// The named field holds a value its encoding cannot carry.
    OutOfRange(&'static str),
    /// A TV information element of unknown type. Its length is not
    /// encoded, so the rest of the message cannot be parsed.
    UnknownInformationElement(u8),
    /// An IPv4 packet that is not what the helper handles.
    UnexpectedPacket(&'static str),
    /// The named checksum does not match.
    InvalidChecksum(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Truncated(what) => write!(f, "truncated {what}"),
            Error::InvalidLength(what) => write!(f, "invalid {what} length"),
            Error::UnsupportedVersion(flags) => {
                write!(f, "not a GTPv1-U message (first octet {flags:#04x})")
            }
            Error::OutOfRange(what) => write!(f, "{what} out of range"),
            Error::UnknownInformationElement(kind) => {
                write!(f, "unknown TV information element type {kind}")
            }
            Error::UnexpectedPacket(what) => write!(f, "unexpected IPv4 packet: {what}"),
            Error::InvalidChecksum(what) => write!(f, "invalid {what} checksum"),
        }
    }
}

impl std::error::Error for Error {}

/// As [`InvalidData`](std::io::ErrorKind::InvalidData), so that `?` also
/// works on the codec's results where an endpoint's are returned.
impl From<Error> for std::io::Error {
    fn from(error: Error) -> Self {
        Self::new(std::io::ErrorKind::InvalidData, error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_io_error_keeps_the_codec_error() {
        let error = std::io::Error::from(Error::Truncated("GTP-U header"));
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert_eq!(
            error.get_ref().and_then(|inner| inner.downcast_ref()),
            Some(&Error::Truncated("GTP-U header"))
        );
    }
}
