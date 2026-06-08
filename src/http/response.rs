use std::collections::HashSet;

use http::header::{HeaderMap, HeaderName, HeaderValue};

/// Headers intended be set on a future `Response`.
#[derive(Debug, Default)]
pub struct PendingHeaders {
    insert: HeaderMap,
    append: HeaderMap,
    remove: HashSet<HeaderName>,
}

impl PendingHeaders {
    /// Return the number of values that this will insert into the `Response` headers.
    pub fn len(&self) -> usize {
        self.insert.len() + self.append.len()
    }

    /// Apply the pending headers to a `Response`.
    pub fn apply(self, headers: &mut HeaderMap) {
        // First, remove any headers we were told to remove:
        for name in self.remove.iter() {
            headers.remove(name);
        }

        // Then, overwrite existing headers with those in `insert_headers`:
        headers.extend(self.insert);

        // And finally append those in `append_headers`:
        let mut name = None;

        for (curr, val) in self.append.into_iter() {
            if curr.is_some() {
                name = curr;
            }

            if let Some(name) = name.as_ref() {
                headers.append(name, val);
            }
        }
    }

    /// Queue a header name and value to eventually insert into the headers of a `Response`.
    ///
    /// When inserted, this will replace any existing headers of the same name.
    pub fn insert(&mut self, name: HeaderName, value: HeaderValue) {
        self.append.remove(&name);
        self.insert.insert(name, value);
    }

    /// Queue a header name and value to eventually append to the headers of a `Response`.
    ///
    /// When appended, this will preserve any already inserted headers of the same name.
    pub fn append(&mut self, name: HeaderName, value: HeaderValue) {
        self.append.append(name, value);
    }

    /// Queue a header name to be removed from the headers of a `Response`.
    ///
    /// In addition to removing any headers of the original `Response`, this will also remove any
    /// previously inserted or appended `PendingHeaders`.
    pub fn remove(&mut self, name: HeaderName) {
        self.insert.remove(&name);
        self.append.remove(&name);
        self.remove.insert(name);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEADER_FOO: HeaderName = HeaderName::from_static("foo");
    const HEADER_BAR: HeaderName = HeaderName::from_static("bar");

    const VALUE_1: HeaderValue = HeaderValue::from_static("1");
    const VALUE_2: HeaderValue = HeaderValue::from_static("2");
    const VALUE_3: HeaderValue = HeaderValue::from_static("3");

    #[test]
    fn test_pending_headers_insert_empty() {
        let mut headers = HeaderMap::default();
        let mut pending = PendingHeaders::default();

        // Insert header into empty map:
        pending.insert(HEADER_FOO, VALUE_1);
        pending.apply(&mut headers);

        assert_eq!(headers.len(), 1);
        assert_eq!(headers.get(HEADER_FOO).unwrap(), VALUE_1);
    }

    #[test]
    fn test_pending_headers_insert_disjoint() {
        let mut headers = HeaderMap::default();
        let mut pending = PendingHeaders::default();

        // Insert header into non-empty map but no matching header name:
        headers.insert(HEADER_BAR, VALUE_1);
        pending.insert(HEADER_FOO, VALUE_2);
        pending.apply(&mut headers);

        assert_eq!(headers.len(), 2);
        assert_eq!(headers.get(HEADER_BAR).unwrap(), VALUE_1);
        assert_eq!(headers.get(HEADER_FOO).unwrap(), VALUE_2);
    }

    #[test]
    fn test_pending_headers_insert_overwrite() {
        let mut headers = HeaderMap::default();
        let mut pending = PendingHeaders::default();

        // Insert and overwrite existing header:
        headers.insert(HEADER_FOO, VALUE_1);
        pending.insert(HEADER_FOO, VALUE_2);
        pending.apply(&mut headers);

        assert_eq!(headers.len(), 1);
        assert_eq!(headers.get(HEADER_FOO).unwrap(), VALUE_2);
    }

    #[test]
    fn test_pending_headers_insert_conflicting() {
        let mut headers = HeaderMap::default();
        let mut pending = PendingHeaders::default();

        // Attempt to insert header multiple times, last write wins:
        pending.insert(HEADER_FOO, VALUE_1);
        pending.insert(HEADER_FOO, VALUE_2);
        pending.insert(HEADER_FOO, VALUE_3);
        pending.apply(&mut headers);

        assert_eq!(headers.len(), 1);
        assert_eq!(headers.get(HEADER_FOO).unwrap(), VALUE_3);
    }

    #[test]
    fn test_pending_headers_append_empty() {
        let mut headers = HeaderMap::default();
        let mut pending = PendingHeaders::default();

        // Append to empty map:
        pending.append(HEADER_FOO, VALUE_1);
        pending.apply(&mut headers);

        assert_eq!(headers.len(), 1);
        assert_eq!(headers.get(HEADER_FOO).unwrap(), VALUE_1);
    }

    #[test]
    fn test_pending_headers_append_disjoint() {
        let mut headers = HeaderMap::default();
        let mut pending = PendingHeaders::default();

        // Append to non-empty map but no existing match for header name:
        headers.append(HEADER_BAR, VALUE_1);
        pending.append(HEADER_FOO, VALUE_2);
        pending.apply(&mut headers);

        assert_eq!(headers.len(), 2);
        assert_eq!(headers.get(HEADER_BAR).unwrap(), VALUE_1);
        assert_eq!(headers.get(HEADER_FOO).unwrap(), VALUE_2);
    }

    #[test]
    fn test_pending_headers_append_overlap() {
        let mut headers = HeaderMap::default();
        let mut pending = PendingHeaders::default();

        // Successful append:
        headers.append(HEADER_FOO, VALUE_1);
        pending.append(HEADER_FOO, VALUE_2);
        pending.apply(&mut headers);

        assert_eq!(headers.len(), 2);
        assert_eq!(
            headers.get_all(HEADER_FOO).into_iter().collect::<Vec<_>>(),
            &[VALUE_1, VALUE_2]
        );
    }

    #[test]
    fn test_pending_headers_remove_empty() {
        let mut headers = HeaderMap::default();
        let mut pending = PendingHeaders::default();

        // Nothing to remove:
        pending.remove(HEADER_FOO);
        pending.apply(&mut headers);

        assert_eq!(headers.len(), 0);
        assert_eq!(headers.get(HEADER_FOO), None);
    }

    #[test]
    fn test_pending_headers_remove_disjoint() {
        let mut headers = HeaderMap::default();
        let mut pending = PendingHeaders::default();

        // Remove targets different header:
        headers.insert(HEADER_BAR, VALUE_1);
        pending.remove(HEADER_FOO);
        pending.apply(&mut headers);

        assert_eq!(headers.len(), 1);
        assert_eq!(headers.get(HEADER_BAR).unwrap(), VALUE_1);
        assert_eq!(headers.get(HEADER_FOO), None);
    }

    #[test]
    fn test_pending_headers_remove_overlap() {
        let mut headers = HeaderMap::default();
        let mut pending = PendingHeaders::default();

        // Successful remove:
        headers.insert(HEADER_FOO, VALUE_1);
        pending.remove(HEADER_FOO);
        pending.apply(&mut headers);

        assert_eq!(headers.len(), 0);
        assert_eq!(headers.get(HEADER_FOO), None);
    }

    #[test]
    fn test_pending_headers_remove_after_insertion() {
        let mut headers = HeaderMap::default();
        let mut pending = PendingHeaders::default();

        // Remove after pending insert and append removes them, too:
        pending.insert(HEADER_FOO, VALUE_1);
        pending.append(HEADER_FOO, VALUE_2);
        pending.remove(HEADER_FOO);
        pending.apply(&mut headers);

        assert_eq!(headers.len(), 0);
        assert_eq!(headers.get(HEADER_FOO), None);
    }

    #[test]
    fn test_pending_headers_insertion_after_remove() {
        let mut headers = HeaderMap::default();
        let mut pending = PendingHeaders::default();

        // Insert and append after pending remove works:
        pending.remove(HEADER_FOO);
        pending.insert(HEADER_FOO, VALUE_1);
        pending.append(HEADER_FOO, VALUE_2);
        pending.apply(&mut headers);

        assert_eq!(headers.len(), 2);
        assert_eq!(
            headers.get_all(HEADER_FOO).into_iter().collect::<Vec<_>>(),
            &[VALUE_1, VALUE_2]
        );
    }

    #[test]
    fn test_pending_headers_insert_after_append() {
        let mut headers = HeaderMap::default();
        let mut pending = PendingHeaders::default();

        // Insert after append clears pending append:
        pending.append(HEADER_FOO, VALUE_1);
        pending.append(HEADER_FOO, VALUE_2);
        pending.insert(HEADER_FOO, VALUE_3);
        pending.apply(&mut headers);

        assert_eq!(headers.len(), 1);
        assert_eq!(headers.get(HEADER_FOO).unwrap(), VALUE_3);
    }
}
