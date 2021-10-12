#[link(wasm_import_module = "fastly_dns")]
extern "C" {

    fn lookup_addr(name: *const u8, name_len: usize, handle_p: *mut u32) -> i32;

    fn lookup_reverse(ip: *const u8, ip_len: usize, handle_p: *mut u32) -> i32;

    fn lookup_txt(name: *const u8, name_len: usize, handle_p: *mut u32) -> i32;

    fn lookup_wait(
        handle: u32,
        buf: *mut u8,
        buf_len: usize,
        pos: u32,
        next: *mut i64,
        written: *mut usize,
    ) -> i32;

    fn lookup_raw(query: *const u8, query_len: usize, handle_p: *mut u32) -> i32;

    fn lookup_wait_raw(
        handle: u32,
        response: *mut u8,
        response_len: usize,
        written: *mut usize,
    ) -> i32;
}
fn main() {
    let name = b"example.com";
    let mut buf = [0u8; 1024];
    let pos = 0;
    let mut next = 0;
    let mut written = 0;
    let res = unsafe {
        let mut handle = 0;
        lookup_addr(name.as_ptr(), name.len(), &mut handle);
        lookup_wait(
            handle,
            buf.as_mut_ptr(),
            buf.len(),
            pos,
            &mut next,
            &mut written,
        )
    };
    assert_eq!(res, 0);

    let ip = b"8.8.8.8";
    let res = unsafe {
        let mut handle = 0;
        lookup_reverse(ip.as_ptr(), ip.len(), &mut handle);
        lookup_wait(
            handle,
            buf.as_mut_ptr(),
            buf.len(),
            pos,
            &mut next,
            &mut written,
        )
    };
    assert_eq!(res, 0);

    let res = unsafe {
        let mut handle = 0;
        lookup_txt(name.as_ptr(), name.len(), &mut handle);
        lookup_wait(
            handle,
            buf.as_mut_ptr(),
            buf.len(),
            pos,
            &mut next,
            &mut written,
        )
    };
    assert_eq!(res, 0);

    let query_raw = [
        0x0eu8, 0x5b, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
        0x00, 0x01,
    ];
    let res = unsafe {
        let mut handle = 0;
        lookup_raw(query_raw.as_ptr(), query_raw.len(), &mut handle);
        lookup_wait_raw(handle, buf.as_mut_ptr(), buf.len(), &mut written)
    };
    assert_eq!(res, 0);
}
