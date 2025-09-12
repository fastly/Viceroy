type MultiValueCursor = u32;

/// Write multiple values out to a single buffer, until the iterator is exhausted, or `max_len`
/// bytes have been written. In the case that there are still values remaining, the second value of
/// the returned tuple will be `Some`.
///
/// If it's not possible to fit a single value inside a buffer of length `max_len`, an error will
/// be returned with the size necessary for the first element of the collection.
pub fn write_values<I, T>(
    iter: I,
    terminator: u8,
    max_len: usize,
    cursor_start: MultiValueCursor,
) -> Result<(Vec<u8>, Option<MultiValueCursor>), usize>
where
    I: Iterator<Item = T>,
    T: AsRef<[u8]>,
{
    let mut buf = Vec::with_capacity(max_len);

    let mut cursor = cursor_start;
    let mut finished = true;
    let skip_amt = usize::try_from(cursor).expect("u32 can fit in usize");
    for item in iter.skip(skip_amt) {
        let bytes = item.as_ref();

        let needed = buf.len() + bytes.len() + 1;
        if needed > max_len {
            // If we haven't written a single entry yet, return an error indicating how much space
            // we would need to write a single entry.
            if cursor == cursor_start {
                return Err(needed);
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
