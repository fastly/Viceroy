type MultiValueCursor = u32;

/// Write multiple values out to a single buffer, until the iterator is exhausted, or `max_len`
/// bytes have been written. In the case that there are still values remaining, the second value of
/// the returned tuple will be `Some`.
pub fn write_values<I, T>(
    iter: I,
    terminator: u8,
    max_len: usize,
    mut cursor: MultiValueCursor,
) -> (Vec<u8>, Option<MultiValueCursor>)
where
    I: Iterator<Item = T>,
    T: AsRef<[u8]>,
{
    let mut buf = Vec::with_capacity(max_len);

    let mut finished = true;
    let skip_amt = usize::try_from(cursor).expect("u32 can fit in usize");
    for item in iter.skip(skip_amt) {
        let bytes = item.as_ref();

        let needed = buf.len() + bytes.len() + 1;
        if needed > max_len {
            finished = false;
            break;
        }

        buf.extend(bytes);
        buf.push(terminator);

        cursor += 1
    }

    let cursor = if finished { None } else { Some(cursor) };

    (buf, cursor)
}
