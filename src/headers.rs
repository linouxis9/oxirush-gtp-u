//! The list of the extension headers of a message.

use std::fmt;
use std::ops::{Deref, DerefMut};

use crate::ExtensionHeader;

/// The extension headers of a message, in their order on the wire
/// (TS 29.281 §5.2).
///
/// It is read and changed as the slice `[ExtensionHeader]` that it
/// dereferences to, and grows with [`push`](Self::push), as a `Vec` does. The
/// first header is kept in the list itself: a message without extension
/// header, or with one, such as the PDU Session Container of a G-PDU on N3,
/// is decoded and made without an allocation for its list. A second header
/// moves the list to the heap.
///
/// ```
/// use oxirush_gtp_u::{
///     ExtensionHeader, ExtensionHeaderType, ExtensionHeaders, Packet, PduSessionContainer,
/// };
///
/// # fn main() -> Result<(), oxirush_gtp_u::Error> {
/// // A message gets its headers one at a time, or all at once
/// let mut packet = Packet::uplink(0x1234_5678, 9, b"an IP packet".to_vec());
/// packet.extension_headers.push(ExtensionHeader::UdpPort(2152));
/// let unknown = ExtensionHeader::Other {
///     kind: ExtensionHeaderType(0x21),
///     content: vec![1, 2],
/// };
/// packet.extension_headers.push(unknown.clone());
/// let same = ExtensionHeaders::from([
///     ExtensionHeader::PduSessionContainer(PduSessionContainer::uplink(9)),
///     ExtensionHeader::UdpPort(2152),
///     unknown.clone(),
/// ]);
/// assert_eq!(packet.extension_headers, same);
///
/// // A decoded message has every header of the chain, in its order
/// let decoded = Packet::decode(&packet.encode()?)?;
/// let headers = &decoded.extension_headers;
/// let kinds: Vec<u8> = headers.iter().map(|header| header.kind().0).collect();
/// assert_eq!(kinds, [0x85, 0x40, 0x21]);
/// assert_eq!(decoded.extension_headers[2], unknown);
/// assert_eq!(decoded.extension_headers.len(), 3);
///
/// // What a slice cannot do, a `Vec` does
/// let mut headers = Vec::from(decoded.extension_headers);
/// headers.retain(|header| !matches!(header, ExtensionHeader::Other { .. }));
/// packet.extension_headers = headers.into();
/// assert_eq!(packet.extension_headers.len(), 2);
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Default)]
pub struct ExtensionHeaders(List);

#[derive(Clone, Default)]
enum List {
    #[default]
    Empty,
    One(ExtensionHeader),
    Several(Vec<ExtensionHeader>),
}

/// What a `Vec` allocates for its first element of this size: a chain of two
/// to four headers is one allocation.
const FIRST_CAPACITY: usize = 4;

impl ExtensionHeaders {
    /// An empty list.
    #[inline]
    pub const fn new() -> Self {
        Self(List::Empty)
    }

    /// Add `header` at the end.
    #[inline]
    pub fn push(&mut self, header: ExtensionHeader) {
        match &mut self.0 {
            // An empty list has nothing to drop.
            List::Empty => std::mem::forget(std::mem::replace(&mut self.0, List::One(header))),
            List::Several(several) => several.push(header),
            List::One(_) => self.spill(header),
        }
    }

    /// Move the list to the heap, with `header` at its end.
    #[cold]
    fn spill(&mut self, header: ExtensionHeader) {
        let mut several = Vec::with_capacity(FIRST_CAPACITY);
        if let List::One(first) = std::mem::take(&mut self.0) {
            several.push(first);
        }
        several.push(header);
        self.0 = List::Several(several);
    }

    /// Remove every header.
    pub fn clear(&mut self) {
        self.0 = List::Empty;
    }
}

impl Deref for ExtensionHeaders {
    type Target = [ExtensionHeader];

    #[inline]
    fn deref(&self) -> &[ExtensionHeader] {
        match &self.0 {
            List::Empty => &[],
            List::One(header) => std::slice::from_ref(header),
            List::Several(headers) => headers,
        }
    }
}

impl DerefMut for ExtensionHeaders {
    fn deref_mut(&mut self) -> &mut [ExtensionHeader] {
        match &mut self.0 {
            List::Empty => &mut [],
            List::One(header) => std::slice::from_mut(header),
            List::Several(headers) => headers,
        }
    }
}

impl fmt::Debug for ExtensionHeaders {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.iter()).finish()
    }
}

// Two lists are equal when their headers are, wherever they keep them.
impl PartialEq for ExtensionHeaders {
    fn eq(&self, other: &Self) -> bool {
        **self == **other
    }
}

impl Eq for ExtensionHeaders {}

impl PartialEq<[ExtensionHeader]> for ExtensionHeaders {
    fn eq(&self, other: &[ExtensionHeader]) -> bool {
        **self == *other
    }
}

impl<const N: usize> PartialEq<[ExtensionHeader; N]> for ExtensionHeaders {
    fn eq(&self, other: &[ExtensionHeader; N]) -> bool {
        **self == other[..]
    }
}

impl PartialEq<Vec<ExtensionHeader>> for ExtensionHeaders {
    fn eq(&self, other: &Vec<ExtensionHeader>) -> bool {
        **self == other[..]
    }
}

impl From<ExtensionHeader> for ExtensionHeaders {
    /// The list of one header, which it keeps in itself.
    #[inline]
    fn from(header: ExtensionHeader) -> Self {
        Self(List::One(header))
    }
}

impl From<Vec<ExtensionHeader>> for ExtensionHeaders {
    /// The list keeps the `Vec`: nothing is copied.
    fn from(headers: Vec<ExtensionHeader>) -> Self {
        Self(List::Several(headers))
    }
}

impl<const N: usize> From<[ExtensionHeader; N]> for ExtensionHeaders {
    fn from(headers: [ExtensionHeader; N]) -> Self {
        headers.into_iter().collect()
    }
}

impl From<ExtensionHeaders> for Vec<ExtensionHeader> {
    fn from(headers: ExtensionHeaders) -> Self {
        match headers.0 {
            List::Empty => Vec::new(),
            List::One(header) => vec![header],
            List::Several(headers) => headers,
        }
    }
}

impl FromIterator<ExtensionHeader> for ExtensionHeaders {
    fn from_iter<I: IntoIterator<Item = ExtensionHeader>>(headers: I) -> Self {
        let mut list = Self::new();
        list.extend(headers);
        list
    }
}

impl Extend<ExtensionHeader> for ExtensionHeaders {
    fn extend<I: IntoIterator<Item = ExtensionHeader>>(&mut self, headers: I) {
        for header in headers {
            self.push(header);
        }
    }
}

impl<'a> IntoIterator for &'a ExtensionHeaders {
    type Item = &'a ExtensionHeader;
    type IntoIter = std::slice::Iter<'a, ExtensionHeader>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<'a> IntoIterator for &'a mut ExtensionHeaders {
    type Item = &'a mut ExtensionHeader;
    type IntoIter = std::slice::IterMut<'a, ExtensionHeader>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter_mut()
    }
}

impl IntoIterator for ExtensionHeaders {
    type Item = ExtensionHeader;
    type IntoIter = ExtensionHeadersIntoIter;

    fn into_iter(self) -> Self::IntoIter {
        let (one, several) = match self.0 {
            List::Empty => (None, Vec::new()),
            List::One(header) => (Some(header), Vec::new()),
            List::Several(headers) => (None, headers),
        };
        ExtensionHeadersIntoIter(one.into_iter().chain(several))
    }
}

/// The headers of an [`ExtensionHeaders`], taken out of it in their order:
/// what its `into_iter` returns.
#[derive(Clone, Debug)]
pub struct ExtensionHeadersIntoIter(
    std::iter::Chain<std::option::IntoIter<ExtensionHeader>, std::vec::IntoIter<ExtensionHeader>>,
);

impl Iterator for ExtensionHeadersIntoIter {
    type Item = ExtensionHeader;

    fn next(&mut self) -> Option<ExtensionHeader> {
        self.0.next()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.0.size_hint()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ExtensionHeaderType, PduSessionContainer};

    fn headers(count: usize) -> Vec<ExtensionHeader> {
        (0..count)
            .map(|index| match index % 3 {
                0 => ExtensionHeader::PduSessionContainer(PduSessionContainer::uplink(index as u8)),
                1 => ExtensionHeader::UdpPort(index as u16),
                _ => ExtensionHeader::Other {
                    kind: ExtensionHeaderType(0x21),
                    content: vec![index as u8, 0],
                },
            })
            .collect()
    }

    /// A list of each length as every way of making one gives it.
    fn lists(expected: &[ExtensionHeader]) -> Vec<ExtensionHeaders> {
        let mut pushed = ExtensionHeaders::new();
        for header in expected {
            pushed.push(header.clone());
        }
        let mut extended = ExtensionHeaders::default();
        extended.extend(expected.iter().cloned());
        vec![
            pushed,
            extended,
            expected.to_vec().into(),
            expected.iter().cloned().collect(),
        ]
    }

    #[test]
    fn a_list_is_its_headers_in_their_order_however_it_was_made() {
        for count in 0..=9 {
            let expected = headers(count);
            for list in lists(&expected) {
                assert_eq!(list.len(), count);
                assert_eq!(list.is_empty(), count == 0);
                assert_eq!(&list[..], &expected[..]);
                assert_eq!(list, expected);
                assert_eq!(list, expected[..]);
                assert_eq!(list.first(), expected.first());
                assert_eq!(format!("{list:?}"), format!("{expected:?}"));
                // Equal to every other list of the same headers
                for other in lists(&expected) {
                    assert_eq!(list, other);
                }
                assert_eq!(list.clone(), list);
                let by_reference: Vec<_> = (&list).into_iter().cloned().collect();
                assert_eq!(by_reference, expected);
                let taken = list.clone().into_iter();
                assert_eq!(taken.size_hint(), (count, Some(count)));
                assert_eq!(taken.collect::<Vec<_>>(), expected);
                assert_eq!(Vec::from(list), expected);
            }
        }
        assert_eq!(
            ExtensionHeaders::from([ExtensionHeader::UdpPort(1)]),
            [ExtensionHeader::UdpPort(1)]
        );
        assert_eq!(ExtensionHeaders::from([]), ExtensionHeaders::new());
        assert_eq!(
            ExtensionHeaders::from(ExtensionHeader::UdpPort(1)),
            [ExtensionHeader::UdpPort(1)]
        );
    }

    #[test]
    fn lists_of_other_headers_or_another_length_differ() {
        for count in 0..=5 {
            let expected = headers(count);
            for list in lists(&expected) {
                let mut longer = list.clone();
                longer.push(ExtensionHeader::UdpPort(0));
                assert_ne!(list, longer);
                assert_eq!(longer.len(), count + 1);
                assert_eq!(longer.last(), Some(&ExtensionHeader::UdpPort(0)));
                if count > 0 {
                    let mut changed = list.clone();
                    changed[count - 1] = ExtensionHeader::UdpPort(0xffff);
                    assert_ne!(list, changed);
                    for (port, header) in (&mut changed).into_iter().enumerate() {
                        *header = ExtensionHeader::UdpPort(port as u16);
                    }
                    assert_eq!(
                        changed[count - 1],
                        ExtensionHeader::UdpPort(count as u16 - 1)
                    );
                    assert!(
                        changed
                            .iter()
                            .all(|header| header.kind() == ExtensionHeaderType::UDP_PORT)
                    );
                }
            }
        }
    }

    #[test]
    fn a_cleared_list_is_empty_and_takes_headers_again() {
        for count in 0..=5 {
            for mut list in lists(&headers(count)) {
                list.clear();
                assert!(list.is_empty());
                assert_eq!(list, ExtensionHeaders::new());
                list.push(ExtensionHeader::UdpPort(1));
                assert_eq!(list, [ExtensionHeader::UdpPort(1)]);
            }
        }
    }
}
