use crate::component::bindings::fastly::compute::types;
use crate::error::Error;
use http::{HeaderMap, HeaderName};
use std::cmp::min;

type MultiValueCursor = u32;

/// How long is a `HeaderName` allowed to be?
const MAX_HEADER_NAME_LEN: usize = 1 << (16 - 1);

/// Write multiple values out to a single buffer, until the iterator is exhausted, or `max_len`
/// bytes have been written. In the case that there are still values remaining, the second value of
/// the returned tuple will be `Some`.
///
/// If it's not possible to fit a single value inside a buffer of length `max_len`, an error will
/// be returned with the size necessary for the first element of the collection.
fn write_values<I, T>(
    iter: I,
    terminator: u8,
    max_len: u64,
    cursor_start: MultiValueCursor,
) -> Result<(Vec<u8>, Option<MultiValueCursor>), types::Error>
where
    I: Iterator<Item = T>,
    T: AsRef<[u8]>,
{
    // Reserve `max_len` bytes, unless it's unreasonably large.
    let mut buf = Vec::with_capacity(min(max_len, 0x1_0000) as usize);

    let mut cursor = cursor_start;
    let mut finished = true;
    let skip_amt = usize::try_from(cursor).expect("u32 can fit in usize");
    for item in iter.skip(skip_amt) {
        let bytes = item.as_ref();

        let needed = buf.len() as u64 + bytes.len() as u64 + 1;
        if needed > max_len {
            // If we haven't written a single entry yet, return an error indicating how much space
            // we would need to write a single entry.
            if cursor == cursor_start {
                return Err(types::Error::BufferLen(needed));
            }

            finished = false;
            break;
        }

        buf.extend(bytes);
        buf.push(terminator);

        cursor += 1
    }

    let cursor = if finished { None } else { Some(cursor) };

    Ok((buf, cursor))
}

/// Similar to `write_values`, but works on strings instead of byte vectors.
fn write_names<I, T>(
    iter: I,
    terminator: char,
    max_len: u64,
    cursor_start: MultiValueCursor,
) -> Result<(String, Option<u32>), types::Error>
where
    I: Iterator<Item = T>,
    T: AsRef<str>,
{
    // Reserve `max_len` bytes, unless it's unreasonably large.
    let mut buf = String::with_capacity(min(max_len, 0x1_0000) as usize);

    let mut cursor = cursor_start;
    let mut finished = true;
    let skip_amt = usize::try_from(cursor).expect("u32 can fit in usize");
    for item in iter.skip(skip_amt) {
        let key = item.as_ref();

        let needed = buf.len() as u64 + key.len() as u64 + 1;
        if needed > max_len {
            // If we haven't written a single entry yet, return an error indicating how much space
            // we would need to write a single entry.
            if cursor == cursor_start {
                // Signal the number of bytes necessary to fit this method, to
                // indicate an error condition.
                return Err(types::Error::BufferLen(needed));
            }

            finished = false;
            break;
        }

        buf += key;
        buf.push(terminator);

        cursor += 1
    }

    let cursor = if finished { None } else { Some(cursor) };

    // At this point we know that the buffer being empty will also mean that there are no
    // remaining entries to read.
    debug_assert!(!buf.is_empty() || cursor.is_none());
    Ok((buf, cursor))
}

/// Fetch all names from a `HeaderMap`.
pub fn get_names<Keys, T>(
    keys: Keys,
    max_len: u64,
    cursor: u32,
) -> Result<(String, Option<u32>), types::Error>
where
    Keys: Iterator<Item = T>,
    T: AsRef<str>,
{
    write_names(keys, '\0', max_len, cursor)
}

/// Fetch all values for a header from a `HeaderMap`.
pub fn get_values(
    headers: &HeaderMap,
    name: &str,
    max_len: u64,
    cursor: u32,
) -> Result<(Vec<u8>, Option<u32>), types::Error> {
    if name.len() > MAX_HEADER_NAME_LEN {
        return Err(Error::InvalidArgument.into());
    }

    let values = headers.get_all(HeaderName::try_from(name)?);
    Ok(write_values(values.into_iter(), b'\0', max_len, cursor)?)
}
