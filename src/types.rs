//! The numbers that say what a message, an extension header, an information
//! element or a cause is, with the names that the specifications give them.

use std::fmt;

/// A type of numbers of one octet, of which some have a name.
macro_rules! named_numbers {
    (
        $(#[$meta:meta])*
        $name:ident, $number:literal;
        $($(#[$constant_meta:meta])* $constant:ident = $value:literal, $text:literal;)*
    ) => {
        $(#[$meta])*
        ///
        /// Any number is a value: one that has no name here is kept, and
        /// encoded, as it is. `Display` prints the name, or the number;
        /// `Debug` prints both.
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(pub u8);

        impl $name {
            $($(#[$constant_meta])* pub const $constant: Self = Self($value);)*

            /// The name that the specification gives the number, for those
            /// that have a constant here.
            pub const fn name(self) -> Option<&'static str> {
                match self.0 {
                    $($value => Some($text),)*
                    _ => None,
                }
            }
        }

        impl From<u8> for $name {
            fn from(number: u8) -> Self {
                Self(number)
            }
        }

        impl From<$name> for u8 {
            fn from(value: $name) -> u8 {
                value.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                match self.name() {
                    Some(name) => f.write_str(name),
                    None => write!(f, $number, self.0),
                }
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                match self.name() {
                    Some(name) => write!(f, concat!("{} (", $number, ")"), name, self.0),
                    None => write!(f, concat!(stringify!($name), "(", $number, ")"), self.0),
                }
            }
        }
    };
}

named_numbers! {
    /// The type of a GTP-U message (TS 29.281 §6.1).
    ///
    /// ```
    /// use oxirush_gtp_u::{MessageType, Packet};
    ///
    /// let response = Packet::echo_response(7);
    /// assert_eq!(response.message_type, MessageType::ECHO_RESPONSE);
    /// assert_eq!(response.message_type.to_string(), "Echo Response");
    /// assert_eq!(format!("{:?}", response.message_type), "Echo Response (2)");
    /// // A type of another protocol of the GTP family
    /// assert_eq!(format!("{:?}", MessageType(16)), "MessageType(16)");
    /// ```
    MessageType, "{}";
    /// Echo Request (§7.2.1).
    ECHO_REQUEST = 1, "Echo Request";
    /// Echo Response (§7.2.2).
    ECHO_RESPONSE = 2, "Echo Response";
    /// Error Indication (§7.3.1).
    ERROR_INDICATION = 26, "Error Indication";
    /// Supported Extension Headers Notification (§7.2.3).
    SUPPORTED_EXTENSION_HEADERS_NOTIFICATION = 31, "Supported Extension Headers Notification";
    /// Tunnel Status (§7.3.3).
    TUNNEL_STATUS = 253, "Tunnel Status";
    /// End Marker (§7.3.2).
    END_MARKER = 254, "End Marker";
    /// G-PDU: a T-PDU, the user's IP packet, in a tunnel.
    G_PDU = 255, "G-PDU";
}

named_numbers! {
    /// The type of a GTP-U extension header (TS 29.281 figure 5.2.1-3). It is
    /// printed in hexadecimal, as the specification writes it in binary.
    ExtensionHeaderType, "{:#04x}";
    /// Long PDCP PDU Number, the value that current senders use.
    LONG_PDCP_PDU_NUMBER = 0x03, "Long PDCP PDU Number";
    /// PDU Set Information Container, the value that current senders use.
    PDU_SET_INFORMATION_CONTAINER = 0x04, "PDU Set Information Container";
    /// Service Class Indicator.
    SERVICE_CLASS_INDICATOR = 0x20, "Service Class Indicator";
    /// UDP Port.
    UDP_PORT = 0x40, "UDP Port";
    /// RAN Container.
    RAN_CONTAINER = 0x81, "RAN Container";
    /// Long PDCP PDU Number, as sent by earlier releases.
    LONG_PDCP_PDU_NUMBER_LEGACY = 0x82, "Long PDCP PDU Number";
    /// Xw RAN Container.
    XW_RAN_CONTAINER = 0x83, "Xw RAN Container";
    /// NR RAN Container.
    NR_RAN_CONTAINER = 0x84, "NR RAN Container";
    /// PDU Session Container.
    PDU_SESSION_CONTAINER = 0x85, "PDU Session Container";
    /// PDU Set Information Container, as sent by earlier versions.
    PDU_SET_INFORMATION_CONTAINER_LEGACY = 0x86, "PDU Set Information Container";
    /// PDCP PDU Number.
    PDCP_PDU_NUMBER = 0xc0, "PDCP PDU Number";
}

impl ExtensionHeaderType {
    /// Whether an endpoint that does not know this type must discard the
    /// message (bit 8 of the type, TS 29.281 §5.2.1).
    pub const fn comprehension_required(self) -> bool {
        self.0 & 0x80 != 0
    }
}

named_numbers! {
    /// The type of a GTP-U information element (TS 29.281 table 8.1-1).
    /// Below 128 an element has a fixed length and no length field (TV);
    /// from 128 it has one (TLV).
    InformationElementType, "{}";
    /// Cause, a TV element of TS 29.060 §7.7.1.
    CAUSE = 1, "Cause";
    /// Recovery, a TV element.
    RECOVERY = 14, "Recovery";
    /// TEID Data I, a TV element.
    TEID_DATA_I = 16, "TEID Data I";
    /// GTP-U Peer Address.
    GTP_U_PEER_ADDRESS = 133, "GTP-U Peer Address";
    /// Extension Header Type List, a TLV element with a one-octet length.
    EXTENSION_HEADER_TYPE_LIST = 141, "Extension Header Type List";
    /// GTP-U Tunnel Status Information, kept as
    /// [`Other`](crate::InformationElement::Other).
    GTP_U_TUNNEL_STATUS_INFORMATION = 230, "GTP-U Tunnel Status Information";
    /// Recovery Time Stamp, kept as
    /// [`Other`](crate::InformationElement::Other): the start time of the
    /// sender, in the first four octets of an NTP timestamp.
    RECOVERY_TIME_STAMP = 231, "Recovery Time Stamp";
    /// Private Extension.
    PRIVATE_EXTENSION = 255, "Private Extension";
}

named_numbers! {
    /// The value of a Cause information element (TS 29.060 table 38). The
    /// names here are those of the causes that a GTP-U node can give or
    /// get; the others of the table are about PDP contexts.
    Cause, "{}";
    /// Request accepted.
    REQUEST_ACCEPTED = 128, "Request accepted";
    /// Non-existent.
    NON_EXISTENT = 192, "Non-existent";
    /// Invalid message format: what an endpoint answers an Echo Request
    /// whose length or information elements are wrong with (TS 29.060
    /// §11.1).
    INVALID_MESSAGE_FORMAT = 193, "Invalid message format";
    /// Version not supported.
    VERSION_NOT_SUPPORTED = 198, "Version not supported";
    /// No resources available.
    NO_RESOURCES_AVAILABLE = 199, "No resources available";
    /// Service not supported.
    SERVICE_NOT_SUPPORTED = 200, "Service not supported";
    /// Mandatory IE incorrect.
    MANDATORY_IE_INCORRECT = 201, "Mandatory IE incorrect";
    /// Mandatory IE missing.
    MANDATORY_IE_MISSING = 202, "Mandatory IE missing";
    /// Optional IE incorrect.
    OPTIONAL_IE_INCORRECT = 203, "Optional IE incorrect";
    /// System failure.
    SYSTEM_FAILURE = 204, "System failure";
    /// Unknown mandatory extension header.
    UNKNOWN_MANDATORY_EXTENSION_HEADER = 214, "Unknown mandatory extension header";
}

/// A TEID as `Debug` prints it: eight hexadecimal digits.
pub(crate) struct Teid(pub(crate) u32);

impl fmt::Debug for Teid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#010x}", self.0)
    }
}

/// Octets as `Debug` prints them: how many there are, then all of them in
/// hexadecimal.
pub(crate) struct Octets<'a>(pub(crate) &'a [u8]);

impl fmt::Debug for Octets<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0.len() {
            1 => f.write_str("1 octet")?,
            length => write!(f, "{length} octets")?,
        }
        if !self.0.is_empty() {
            f.write_str(" ")?;
        }
        self.0.iter().try_for_each(|octet| write!(f, "{octet:02x}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_number_prints_its_name_and_keeps_its_value() {
        assert_eq!(MessageType::G_PDU, MessageType(255));
        assert_eq!(MessageType::from(255), MessageType::G_PDU);
        assert_eq!(u8::from(MessageType::END_MARKER), 254);
        assert_eq!(MessageType::G_PDU.to_string(), "G-PDU");
        assert_eq!(format!("{:?}", MessageType::G_PDU), "G-PDU (255)");
        assert_eq!(MessageType(77).name(), None);
        assert_eq!(MessageType(77).to_string(), "77");
        assert_eq!(format!("{:?}", MessageType(77)), "MessageType(77)");

        let container = ExtensionHeaderType::PDU_SESSION_CONTAINER;
        assert_eq!(container.to_string(), "PDU Session Container");
        assert_eq!(format!("{container:?}"), "PDU Session Container (0x85)");
        assert_eq!(ExtensionHeaderType(0x21).to_string(), "0x21");
        assert_eq!(
            format!("{:?}", ExtensionHeaderType(1)),
            "ExtensionHeaderType(0x01)"
        );
        // Both values of a header that changed its type have its name.
        assert_eq!(
            ExtensionHeaderType::LONG_PDCP_PDU_NUMBER.name(),
            ExtensionHeaderType::LONG_PDCP_PDU_NUMBER_LEGACY.name()
        );

        assert_eq!(
            format!("{:?}", InformationElementType::TEID_DATA_I),
            "TEID Data I (16)"
        );
        assert_eq!(
            format!("{:?}", Cause::INVALID_MESSAGE_FORMAT),
            "Invalid message format (193)"
        );
        assert_eq!(format!("{:?}", Cause(211)), "Cause(211)");
        // A value is matched by its constant.
        assert!(matches!(MessageType(1), MessageType::ECHO_REQUEST));
    }

    /// Bits 8 and 7 of a type, as figure 5.2.1-2 gives them.
    #[test]
    fn the_types_of_the_specification_say_who_must_understand_them() {
        for (kind, required) in [
            (ExtensionHeaderType::LONG_PDCP_PDU_NUMBER, false),
            (ExtensionHeaderType::PDU_SET_INFORMATION_CONTAINER, false),
            (ExtensionHeaderType::SERVICE_CLASS_INDICATOR, false),
            (ExtensionHeaderType::UDP_PORT, false),
            (ExtensionHeaderType::RAN_CONTAINER, true),
            (ExtensionHeaderType::LONG_PDCP_PDU_NUMBER_LEGACY, true),
            (ExtensionHeaderType::XW_RAN_CONTAINER, true),
            (ExtensionHeaderType::NR_RAN_CONTAINER, true),
            (ExtensionHeaderType::PDU_SESSION_CONTAINER, true),
            (
                ExtensionHeaderType::PDU_SET_INFORMATION_CONTAINER_LEGACY,
                true,
            ),
            (ExtensionHeaderType::PDCP_PDU_NUMBER, true),
        ] {
            assert_eq!(kind.comprehension_required(), required, "{kind:?}");
        }
    }

    #[test]
    fn octets_and_teids_are_printed_in_hexadecimal() {
        assert_eq!(format!("{:?}", Teid(0x1001)), "0x00001001");
        assert_eq!(format!("{:?}", Octets(&[])), "0 octets");
        assert_eq!(format!("{:?}", Octets(&[7])), "1 octet 07");
        assert_eq!(format!("{:?}", Octets(&[0x45, 0, 0xff])), "3 octets 4500ff");
    }
}
