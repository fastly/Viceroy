use crate::bindings::wasi::cli::{stderr, stdin, stdout};
use crate::bindings::wasi::io::streams::{InputStream, OutputStream};
use crate::{State, TrappingUnwrap};
use core::cell::{Cell, OnceCell, UnsafeCell};
use core::mem::MaybeUninit;
use wasi::{Errno, Fd};

pub const MAX_DESCRIPTORS: usize = 128;

#[repr(C)]
pub enum Descriptor {
    /// A closed descriptor, holding a reference to the previous closed
    /// descriptor to support reusing them.
    Closed(Option<Fd>),

    /// Input and/or output wasi-streams, along with stream metadata.
    Streams(Streams),

    Bad,
}

/// Input and/or output wasi-streams, along with a stream type that
/// identifies what kind of stream they are and possibly supporting
/// type-specific operations like seeking.
pub struct Streams {
    /// The input stream, if present.
    pub input: OnceCell<InputStream>,

    /// The output stream, if present.
    pub output: OnceCell<OutputStream>,

    /// Information about the source of the stream.
    pub type_: StreamType,
}

impl Streams {
    /// Return the input stream, initializing it on the fly if needed.
    pub fn get_read_stream(&self) -> Result<&InputStream, Errno> {
        match self.input.get() {
            Some(wasi_stream) => Ok(wasi_stream),

            // proxy worlds don't have filesystem access
            None => Err(wasi::ERRNO_BADF),
        }
    }

    /// Return the output stream, initializing it on the fly if needed.
    pub fn get_write_stream(&self) -> Result<&OutputStream, Errno> {
        match self.output.get() {
            Some(wasi_stream) => Ok(wasi_stream),

            // proxy worlds don't have filesystem access
            None => Err(wasi::ERRNO_BADF),
        }
    }
}

pub enum StreamType {
    /// Streams for implementing stdio.
    Stdio,
}

#[repr(C)]
pub struct Descriptors {
    /// Storage of mapping from preview1 file descriptors to preview2 file
    /// descriptors.
    table: UnsafeCell<MaybeUninit<[Descriptor; MAX_DESCRIPTORS]>>,
    table_len: Cell<u16>,

    /// Points to the head of a free-list of closed file descriptors.
    closed: Option<Fd>,
}

impl Descriptors {
    pub fn new(_state: &State) -> Self {
        let d = Descriptors {
            table: UnsafeCell::new(MaybeUninit::uninit()),
            table_len: Cell::new(0),
            closed: None,
        };

        fn new_once<T>(val: T) -> OnceCell<T> {
            let cell = OnceCell::new();
            let _ = cell.set(val);
            cell
        }

        d.push(Descriptor::Streams(Streams {
            input: new_once(stdin::get_stdin()),
            output: OnceCell::new(),
            type_: StreamType::Stdio,
        }))
        .trapping_unwrap();
        d.push(Descriptor::Streams(Streams {
            input: OnceCell::new(),
            output: new_once(stdout::get_stdout()),
            type_: StreamType::Stdio,
        }))
        .trapping_unwrap();
        d.push(Descriptor::Streams(Streams {
            input: OnceCell::new(),
            output: new_once(stderr::get_stderr()),
            type_: StreamType::Stdio,
        }))
        .trapping_unwrap();

        d
    }

    fn push(&self, desc: Descriptor) -> Result<Fd, Errno> {
        unsafe {
            let table = (*self.table.get()).as_mut_ptr();
            let len = usize::try_from(self.table_len.get()).trapping_unwrap();
            if len >= (*table).len() {
                return Err(wasi::ERRNO_NOMEM);
            }
            core::ptr::addr_of_mut!((*table)[len]).write(desc);
            self.table_len.set(u16::try_from(len + 1).trapping_unwrap());
            Ok(Fd::from(u32::try_from(len).trapping_unwrap()))
        }
    }

    fn table(&self) -> &[Descriptor] {
        unsafe {
            std::slice::from_raw_parts(
                (*self.table.get()).as_ptr().cast(),
                usize::try_from(self.table_len.get()).trapping_unwrap(),
            )
        }
    }

    fn table_mut(&mut self) -> &mut [Descriptor] {
        unsafe {
            std::slice::from_raw_parts_mut(
                (*self.table.get()).as_mut_ptr().cast(),
                usize::try_from(self.table_len.get()).trapping_unwrap(),
            )
        }
    }

    pub fn open(&mut self, d: Descriptor) -> Result<Fd, Errno> {
        match self.closed {
            // No closed descriptors: expand table
            None => self.push(d),
            Some(freelist_head) => {
                // Pop an item off the freelist
                let freelist_desc = self.get_mut(freelist_head).trapping_unwrap();
                let next_closed = match freelist_desc {
                    Descriptor::Closed(next) => *next,
                    _ => unreachable!("impossible: freelist points to a closed descriptor"),
                };
                // Write descriptor to the entry at the nead of the list
                *freelist_desc = d;
                // Point closed to the following item
                self.closed = next_closed;
                Ok(freelist_head)
            }
        }
    }

    pub fn get(&self, fd: Fd) -> Result<&Descriptor, Errno> {
        self.table()
            .get(usize::try_from(fd).trapping_unwrap())
            .ok_or(wasi::ERRNO_BADF)
    }

    pub fn get_mut(&mut self, fd: Fd) -> Result<&mut Descriptor, Errno> {
        self.table_mut()
            .get_mut(usize::try_from(fd).trapping_unwrap())
            .ok_or(wasi::ERRNO_BADF)
    }

    // Internal: close a fd, returning the descriptor.
    fn close_(&mut self, fd: Fd) -> Result<Descriptor, Errno> {
        // Throw an error if closing an fd which is already closed
        match self.get(fd)? {
            Descriptor::Closed(_) => Err(wasi::ERRNO_BADF)?,
            _ => {}
        }
        // Mutate the descriptor to be closed, and push the closed fd onto the head of the linked list:
        let last_closed = self.closed;
        let prev = std::mem::replace(self.get_mut(fd)?, Descriptor::Closed(last_closed));
        self.closed = Some(fd);
        Ok(prev)
    }

    // Close an fd.
    pub fn close(&mut self, fd: Fd) -> Result<(), Errno> {
        drop(self.close_(fd)?);
        Ok(())
    }

    // Expand the table by pushing a closed descriptor to the end. Used for renumbering.
    fn push_closed(&mut self) -> Result<(), Errno> {
        let old_closed = self.closed;
        let new_closed = self.push(Descriptor::Closed(old_closed))?;
        self.closed = Some(new_closed);
        Ok(())
    }

    // Implementation of fd_renumber
    pub fn renumber(&mut self, from_fd: Fd, to_fd: Fd) -> Result<(), Errno> {
        // First, ensure from_fd is in bounds:
        let _ = self.get(from_fd)?;
        // Expand table until to_fd is in bounds as well:
        while self.table_len.get() as u32 <= to_fd {
            self.push_closed()?;
        }
        // Then, close from_fd and put its contents into to_fd:
        let desc = self.close_(from_fd)?;
        // TODO FIXME if this overwrites a preopen, do we need to clear it from the preopen table?
        *self.get_mut(to_fd)? = desc;

        Ok(())
    }

    // A bunch of helper functions implemented in terms of the above pub functions:

    pub fn get_read_stream(&self, fd: Fd) -> Result<&InputStream, Errno> {
        match self.get(fd)? {
            Descriptor::Streams(streams) => streams.get_read_stream(),
            Descriptor::Closed(_) | Descriptor::Bad => Err(wasi::ERRNO_BADF),
        }
    }

    pub fn get_write_stream(&self, fd: Fd) -> Result<&OutputStream, Errno> {
        match self.get(fd)? {
            Descriptor::Streams(streams) => streams.get_write_stream(),
            Descriptor::Closed(_) | Descriptor::Bad => Err(wasi::ERRNO_BADF),
        }
    }
}
