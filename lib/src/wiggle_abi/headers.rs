use {
    crate::{error::Error, wiggle_abi::types, wiggle_abi::MultiValueWriter},
    http::{header::HeaderName, HeaderMap, HeaderValue},
    wiggle::{GuestMemory, GuestPtr},
};

/// This constant reflects a similar constant within Hyper, which will panic
/// if given header names longer than this value.
pub const MAX_HEADER_NAME_LEN: u32 = (1 << 16) - 1;

pub(crate) trait HttpHeaders {
    fn names_get(
        &self,
        memory: &mut GuestMemory<'_>,
        buf: GuestPtr<u8>,
        buf_len: u32,
        cursor: types::MultiValueCursor,
        nwritten_out: GuestPtr<u32>,
    ) -> Result<types::MultiValueCursorResult, Error>;

    fn value_get(
        &self,
        memory: &mut GuestMemory<'_>,
        name: GuestPtr<[u8]>,
        value: GuestPtr<u8>,
        value_max_len: u32,
        nwritten_out: GuestPtr<u32>,
    ) -> Result<(), Error>;

    fn values_get(
        &self,
        memory: &mut GuestMemory<'_>,
        name: GuestPtr<[u8]>,
        buf: GuestPtr<u8>,
        buf_len: u32,
        cursor: types::MultiValueCursor,
        nwritten_out: GuestPtr<u32>,
    ) -> Result<types::MultiValueCursorResult, Error>;

    fn values_set(
        &mut self,
        memory: &GuestMemory<'_>,
        name: GuestPtr<[u8]>,
        values: GuestPtr<[u8]>,
    ) -> Result<(), Error>;

    fn insert(
        &mut self,
        memory: &GuestMemory<'_>,
        name: GuestPtr<[u8]>,
        value: GuestPtr<[u8]>,
    ) -> Result<(), Error>;

    fn append(
        &mut self,
        memory: &GuestMemory<'_>,
        name: GuestPtr<[u8]>,
        value: GuestPtr<[u8]>,
    ) -> Result<(), Error>;

    fn remove(&mut self, memory: &GuestMemory<'_>, name: GuestPtr<[u8]>) -> Result<(), Error>;
}

impl HttpHeaders for HeaderMap<HeaderValue> {
    fn names_get(
        &self,
        memory: &mut GuestMemory<'_>,
        buf: GuestPtr<u8>,
        buf_len: u32,
        cursor: types::MultiValueCursor,
        nwritten_out: GuestPtr<u32>,
    ) -> Result<types::MultiValueCursorResult, Error> {
        // order consistency: "The iteration order is arbitrary, but consistent across platforms for the
        // same crate version."
        let mut names_iter = self.keys();
        // Write the values to guest memory
        names_iter.write_values(memory, b'\0', buf.as_array(buf_len), cursor, nwritten_out)
    }

    fn value_get(
        &self,
        memory: &mut GuestMemory<'_>,
        name: GuestPtr<[u8]>,
        value_ptr: GuestPtr<u8>,
        value_max_len: u32,
        nwritten_out: GuestPtr<u32>,
    ) -> Result<(), Error> {
        if name.len() > MAX_HEADER_NAME_LEN {
            return Err(Error::InvalidArgument);
        }

        let value = {
            let name = HeaderName::from_bytes(memory.as_slice(name)?.ok_or(Error::SharedMemory)?)?;
            self.get(&name).ok_or(Error::InvalidArgument)?
        };

        let value_bytes = value.as_ref();
        if value_bytes.len() > value_max_len as usize {
            // Write out the number of bytes necessary to fit this header value, or zero on overflow
            // to signal an error condition.
            memory.write(nwritten_out, value_bytes.len().try_into().unwrap_or(0))?;
            return Err(Error::BufferLengthError {
                buf: "value",
                len: "value_max_len",
            });
        }
        let value_len =
            u32::try_from(value_bytes.len()).expect("smaller than value_max_len means it must fit");
        memory.copy_from_slice(value_bytes, value_ptr.as_array(value_len))?;
        memory.write(nwritten_out, value_len)?;

        Ok(())
    }

    fn values_get(
        &self,
        memory: &mut GuestMemory<'_>,
        name: GuestPtr<[u8]>,
        buf: GuestPtr<u8>,
        buf_len: u32,
        cursor: types::MultiValueCursor,
        nwritten_out: GuestPtr<u32>,
    ) -> Result<types::MultiValueCursorResult, Error> {
        if name.len() > MAX_HEADER_NAME_LEN {
            return Err(Error::InvalidArgument);
        }

        let mut values_iter = {
            let name = HeaderName::from_bytes(memory.as_slice(name)?.ok_or(Error::SharedMemory)?)?;
            self.get_all(&name).iter()
        };

        values_iter.write_values(memory, b'\0', buf.as_array(buf_len), cursor, nwritten_out)
    }

    fn values_set(
        &mut self,
        memory: &GuestMemory<'_>,
        name: GuestPtr<[u8]>,
        values: GuestPtr<[u8]>,
    ) -> Result<(), Error> {
        if name.len() > MAX_HEADER_NAME_LEN {
            return Err(Error::InvalidArgument);
        }

        let name = HeaderName::from_bytes(memory.as_slice(name)?.ok_or(Error::SharedMemory)?)?;
        let values = {
            let values_bytes = memory.as_slice(values)?.ok_or(Error::SharedMemory)?;
            // split slice along nul bytes
            let mut iter = values_bytes.split(|b| *b == 0);
            // drop the empty item at the end
            iter.next_back();
            iter.map(HeaderValue::from_bytes)
                .collect::<Result<Vec<HeaderValue>, _>>()?
        };

        // Remove any values if they exist
        if let http::header::Entry::Occupied(e) = self.entry(&name) {
            e.remove_entry_mult();
        }

        // Add all the new values
        for value in values {
            self.append(&name, value);
        }
        Ok(())
    }

    fn insert(
        &mut self,
        memory: &GuestMemory<'_>,
        name: GuestPtr<[u8]>,
        value: GuestPtr<[u8]>,
    ) -> Result<(), Error> {
        if name.len() > MAX_HEADER_NAME_LEN {
            return Err(Error::InvalidArgument);
        }

        let name = HeaderName::from_bytes(memory.as_slice(name)?.ok_or(Error::SharedMemory)?)?;
        let value = HeaderValue::from_bytes(memory.as_slice(value)?.ok_or(Error::SharedMemory)?)?;
        self.insert(name, value);
        Ok(())
    }

    fn append(
        &mut self,
        memory: &GuestMemory<'_>,
        name: GuestPtr<[u8]>,
        value: GuestPtr<[u8]>,
    ) -> Result<(), Error> {
        if name.len() > MAX_HEADER_NAME_LEN {
            return Err(Error::InvalidArgument);
        }

        let name = HeaderName::from_bytes(memory.as_slice(name)?.ok_or(Error::SharedMemory)?)?;
        let value = HeaderValue::from_bytes(memory.as_slice(value)?.ok_or(Error::SharedMemory)?)?;
        self.append(name, value);
        Ok(())
    }

    fn remove(&mut self, memory: &GuestMemory<'_>, name: GuestPtr<[u8]>) -> Result<(), Error> {
        if name.len() > MAX_HEADER_NAME_LEN {
            return Err(Error::InvalidArgument);
        }

        let name = HeaderName::from_bytes(memory.as_slice(name)?.ok_or(Error::SharedMemory)?)?;
        let _ = self.remove(name).ok_or(Error::InvalidArgument)?;
        Ok(())
    }
}
