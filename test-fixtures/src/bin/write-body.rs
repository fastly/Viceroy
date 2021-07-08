//! A small test fixture used for testing APIs on bodies.
//!
//! A small note: This program uses the `fastly_sys` crate directly, rather than the `fastly` crate
//! (see #50) because [`BodyHandle`][handle-write] doesn't expose a way to write to the front of a
//! body.
//!
//! The bare ABI types are used so that we can test that writing to the front of a body works as
//! expected.
//!
//! [handle-write]: https://docs.rs/fastly/0.4.0/fastly/body/struct.BodyHandle.html#method.write_bytes

use {
    fastly_shared::BodyWriteEnd,
    fastly_sys::{
        fastly_http_body as http_body, fastly_http_resp as http_resp, BodyHandle, ResponseHandle,
    },
};

fn main() {
    // Initialize a body, using the `new` hostcall.
    let mut resp_body: BodyHandle = 0;
    unsafe {
        http_body::new(&mut resp_body)
            .result()
            .expect("can create a new body");
    }

    // Write the string "Viceroy" to the response body, calling `write` twice.
    {
        let msg_1 = "Vice";
        let mut nwritten_1 = 0;
        unsafe {
            http_body::write(
                resp_body,
                msg_1.as_ptr(),
                msg_1.len(),
                BodyWriteEnd::Back,
                &mut nwritten_1,
            )
            .result()
            .expect("can write to the end of a body");
        }
        assert_eq!(nwritten_1, msg_1.len());

        let msg_2 = "roy";
        let mut nwritten_2 = 0;
        unsafe {
            http_body::write(
                resp_body,
                msg_2.as_ptr(),
                msg_2.len(),
                BodyWriteEnd::Back,
                &mut nwritten_2,
            )
            .result()
            .expect("can write to the end of a body");
        }
        assert_eq!(nwritten_2, msg_2.len());
    }

    // Allocate another body, and write a "!" to it. We now now have two bodies: "Viceroy" and "!"
    let other_body = {
        let mut other_body: BodyHandle = 0;
        let msg = "!";
        let mut nwritten = 0;
        unsafe {
            http_body::new(&mut other_body)
                .result()
                .expect("can create a new body");
            http_body::write(
                other_body,
                msg.as_ptr(),
                msg.len(),
                BodyWriteEnd::Back,
                &mut nwritten,
            )
            .result()
            .expect("can write to the end of another body");
        }
        assert_eq!(nwritten, msg.len());
        other_body
    };

    // Append the "!" to our response body, so it contains "Viceroy!"
    unsafe {
        http_body::append(resp_body, other_body)
            .result()
            .expect("bodies can be appended");
    }

    // Write "Hello, " to the *front* of our response body. It should now say "Hello, Viceroy!"
    {
        let hello_msg = "Hello, ";
        let mut nwritten = 0;
        unsafe {
            http_body::write(
                resp_body,
                hello_msg.as_ptr(),
                hello_msg.len(),
                BodyWriteEnd::Front,
                &mut nwritten,
            )
            .result()
            .expect("can write to the end of a body");
        }
        assert_eq!(nwritten, hello_msg.len());
    }

    // Finally, send the response downstream.
    let mut resp: ResponseHandle = 0;
    unsafe {
        http_resp::new(&mut resp)
            .result()
            .expect("can create a new response");
        http_resp::send_downstream(resp, resp_body, 0)
            .result()
            .expect("can send the response downstream");
    }
}
