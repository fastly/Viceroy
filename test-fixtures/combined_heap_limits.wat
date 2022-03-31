(module

  (import "fastly_http_req" "body_downstream_get"
    (func $request_get
      (param i32) (param i32)
      (result i32)))
  (import "fastly_http_req" "header_value_get"
    (func $header_get
      (param $handle i32) (param $name i32) (param $name_len i32) (param $out_value i32) (param $out_value_max_len i32) (param $out_value_written i32)
      (result i32)))

  (import "fastly_http_resp" "new"
    (func $response_new
      (param i32)
      (result i32)))
  (import "fastly_http_resp" "header_insert"
    (func $response_add_header
      (param i32) ;; the handle
      (param i32) (param i32) ;; header string and length
      (param i32) (param i32) ;; value string and length
      (result i32)))
  (import "fastly_http_resp" "status_set"
    (func $response_set_status
      (param i32) (param i32)
      (result i32)))
  (import "fastly_http_resp" "send_downstream"
    (func $response_send
      (param i32) (param i32) (param i32)
      (result i32)))

  (import "fastly_http_body" "new"
    (func $response_new_body
      (param i32)
      (result i32)))
  (import "fastly_http_body" "write"
    (func $response_add_to_body
      (param i32) ;; the handle
      (param i32) ;; the pointer
      (param i32) ;; the length
      (param i32) ;; what end to write to ?
      (param i32) ;; how many bytes were written
      (result i32)))
  (import "fastly_http_body" "close"
    (func $response_done_with_body
      (param i32) ;; the handle
      (result i32)))

  (import "wasi_snapshot_preview1" "clock_time_get"
    (func $what_time_is_it
      (param i32)
      (param i64)
      (param i32)
      (result i32))) 
  (import "wasi_snapshot_preview1" "proc_exit"
    (func $wasi_exit
      (param i32)))

  ;; we're going to fix a few memory locations as constants, just to avoid
  ;; some other messiness, even though it's bad software engineering.
  (global $request_handle_buffer i32 (i32.const 4))
  (global $request_body_buffer i32 (i32.const 8))
  (global $response_handle_buffer i32 (i32.const 12))
  (global $response_body_buffer i32 (i32.const 16))
  (global $amount_written i32 (i32.const 20))
  (global $message_length i32 (i32.const 24))
  (global $loop_time_response i32 (i32.const 32)) ;; actually is 16 bytes, and needs to
                                                  ;; be 8-byte aligned.
  (global $message i32 (i32.const 48))
  (global $message_max_len i32 (i32.const 128))

  ;; these are constant strings, defined at the end of this file. I
  ;; wish there was an easier way to make this connection from here to
  ;; the declared addresses there, but I couldn't figure one out.
  (global $request_guest_kb i32 (i32.const 4096))
  (global $request_body_kb i32 (i32.const 4224))
  (global $request_header_kb i32 (i32.const 4352))
  (global $seconds_to_take i32 (i32.const 4480))
  (global $lorem_ipsum i32 (i32.const 4608))
  (global $response_header_prefix i32 (i32.const 4736))
  (global $response_header_number_start_offset i32 (i32.const 4750)) ;; where to add the number


  (func $main (export "_start")
    (local $start_time i64)
    
    ;; let's save what time we started, so that we can delay appropriately at
    ;; the end
    (i32.const 1) ;; we're looking for the monotonic clock
    (i64.const 1000000000) ;; a precision of 1 second is just fine
    (global.get $loop_time_response)
    (call $what_time_is_it)
    (call $maybe_error_die)
    (global.get $loop_time_response)
    (i64.load)
    (local.set $start_time)

    ;; pick up the request
    (call $load_request)

    ;; first we're going to push up the amount of direct space we can access
    ;; within this particular wasm universe
    (global.get $request_guest_kb)
    (call $get_size) ;; does all the human string -> wasm number conversion, leaving
                     ;; it on the top of the stack  
    (call $extend_heap) ;; extend the heap by the total, which (again) is on
                        ;; top of the stack

    ;; now that we've consumed our unnecessary space, let's start creating
    ;; the response we're going to send back.
    (global.get $response_handle_buffer)
    (call $response_new)
    (call $maybe_error_die) ;; just a handy function that dies if we get
                            ;; an error code from the runtime

    ;; then we're going to add a bunch of headers to our outgoing message,
    ;; to pad it out to the amount of header space we've been asked to
    ;; consume.
    (global.get $request_header_kb)
    (call $get_size) ;; leaves the size on the top of the stack
    (call $add_silly_headers)

    ;; then we're going to extend the body by however many bytes the user
    ;; asked us to include.
    (global.get $request_body_kb)
    (call $get_size)
    (call $add_body)

    ;; then we're going to delay for as long as the user told us to delay
    ;; for.
    (global.get $seconds_to_take)
    (call $get_size)
    (i64.extend_i32_u) ;; get this to the right side, but it's still in seconds
    (i64.const 1000000000)
    (i64.mul) ;; .. and now it's in nanoseconds
    (local.get $start_time)
    (i64.add) ;; now our target time is on top of the stack
    (call $wait_until)

    ;; and if we've survived all that, we're done. mark this as a 200
    ;; response, send it back, and exit out.
    (i32.const 200)
    (call $send_response)
    (i32.const 0)
    (call $wasi_exit)
    unreachable
    )

  ;; extend the heap by the given number of kilobytes. because WebAssembly
  ;; only allows us to operate in terms of 64kb pages, this necessarily
  ;; rounds up. if this operationg fails we return a 500 error and quit
  ;; immediately
  (func $extend_heap (param $size_in_kb i32)
    (local $original_heap_page_count i32)
    (local $page_growth_target i32)

    ;; we're going to get the current memory size now, because it'll
    ;; be handy for computing a fill later.
    (memory.size)
    (local.set $original_heap_page_count)

    ;; compute (size_in_kb + 63) `div` 64, which is a rounded up
    ;; division by 64, which is the amount of heap to add in bytes
    (local.get $size_in_kb)
    (i32.const 63)
    (i32.add)
    (i32.const 64)
    (i32.div_u)
    (local.set $page_growth_target)

    ;; grow the heap size. if this operation fails, then we should immediately
    ;; quit with an error
    (block $grow_grow
       (local.get $page_growth_target)
       (memory.grow)
       (i32.const 0)
       (i32.gt_s)
       (br_if $grow_grow)
       (i32.const 500)
       (call $maybe_error_die))

    ;; Do a little sanity check here. The new size should be the old size
    ;; plus the given amount. If it's not, then something weird happened
    ;; and this test is not working as intended.
    (block $check_grow_worked
      (local.get $original_heap_page_count)
      (local.get $page_growth_target)
      (i32.add)
      (memory.size)
      (i32.eq)
      (br_if $check_grow_worked)
      (i32.const 510)
      (call $maybe_error_die))

    ;; Yay! We allocated memory. Now write some things to it, just to make
    ;; sure the compiler(s) aren't doing anything distressingly clever.
    (local.get $original_heap_page_count)

    ;; memory.fill takes three arguments, in the following order:
    ;;   - the start of the block
    ;;   - the value to fill
    ;;   - the amount of space to fill (in bytes)
    (i32.const 65536)
    (i32.mul) ;; this is the base pointer for our new region. I told you
              ;; it'd be handy!

    (i32.const 0) ;; we want this filled with 0s

    (local.get $page_growth_target)
    (i32.const 65536)
    (i32.mul) ;; the number of bytes to fill
    (memory.fill))
    
  ;; add a bunch of silly headers to this particular message. each header
  ;; will be a 64 byte block of lorem ipsum, just because I didn't want to
  ;; worry about any sort of unicode nonsense.
  (func $add_silly_headers (param $size_in_kb i32)
    (local $i i32)

    ;; compute the number of times we want to go around this loop. our text
    ;; is 64 bytes long (assuming you don't count the null at the end), so
    ;; we need 1024 / 64 = 16 copies of it per KB the user has requested.
    (local.get $size_in_kb)
    (i32.const 16)
    (i32.mul) ;; whee! the total number we need is now on the stack.
    (local.set $i)

    ;; OK, now comes the loopy bit. recall that WASM loops go back to the
    ;; start when you branch to their label, and blocks exit early when
    ;; you jump to their label.
    (loop $header_adding_loop
      (block $while_test
        (local.get $i)
        (i32.const 0)
        (i32.ne)
        (br_if $while_test) ;; in other words, if i != 0 jump out of
                            ;; this block and do the loop body; the
                            ;; rest of this block is just the return
        (return))

      ;; wheee! we get to add a header.
      ;; first step in adding the header: figure out the name of the
      ;; field. this involves using our little int2str helper function,
      ;; which takes the value and a memory offset and returns the offset
      ;; once it's done writing. it will *not* write the terminal null, so
      ;; we'll need to do that.
      (local.get $i)
      (global.get $response_header_number_start_offset)
      (call $int2str)
      (i32.const 0)
      (i32.store8)

      ;; OK, our header string is set up, and we're just using a constant
      ;; body, so we should be good to go.
      (global.get $response_handle_buffer)
      (i32.load)
      (global.get $response_header_prefix)
      (global.get $response_header_prefix) ;; \ These compute the length of the header, and
      (call $strlen)                       ;; / put it on the stack
      (global.get $lorem_ipsum)
      (global.get $lorem_ipsum)            ;; \ these compute the length of the value, and
      (call $strlen)                       ;; / put it on the stack
      (call $response_add_header)
      (call $maybe_error_die)

      ;; OK, we added some data. subtract one from our counter and
      ;; go again.
      (local.get $i)
      (i32.const 1)
      (i32.sub)
      (local.set $i)
      (br $header_adding_loop))
  
    unreachable)


  ;; add a body of the given size. we don't need to be too precious about
  ;; this; HTTP bodies can be pretty much anything. so we're going to
  ;; just write out 1k chunks from the start of our memory, and ignore
  ;; the fact that this leaks internal state everywhere.
  (func $add_body (param $size_in_kb i32)
    (local $bytes_left_to_write i32)

    ;; compute how many bytes to write. we do this because the spec
    ;; allows partial writes, and I don't want to deal with writing
    ;; an inner loop.
    (local.get $size_in_kb)
    (i32.const 1024)
    (i32.mul)
    (local.set $bytes_left_to_write)

    ;; first thing's first: we need to create the body buffer inside
    ;; the runtime
    (global.get $response_body_buffer)
    (call $response_new_body)
    (call $maybe_error_die)

    ;; now we're going to actually write to the buffer.
    (block $body_write_block
      (loop $body_write_loop
        ;; if we've got 0 bytes left to write, let's just stop
        (local.get $bytes_left_to_write)
        (i32.const 0)
        (i32.eq)
        (br_if $body_write_block) ;; remember, this cancels execution of the
                                  ;; rest of the block

        ;; OK, we'll just tack on 1k more data
        (global.get $response_body_buffer)
        (i32.load) ;; push the handle
        (i32.const 0) ;; push the pointer for the buffer; the start of memory,
                      ;; because we don't care
        (i32.const 1024) ;; the length of the buffer
        (i32.const 0) ;; This means add it to the end; it's `body_write_end::back`
                      ;; from `typenames.witx`. It appears that enumerations are
                      ;; numbered in order from zero, for reference.
        (global.get $amount_written)
        (call $response_add_to_body)
        (call $maybe_error_die)

        ;; OK, let's see how many bytes we actually wrote, subtract that
        ;; from our countdown, and loop
        (local.get $bytes_left_to_write) ;; stack: [bytes_left_to_write]
        (global.get $amount_written) ;; stack: [bytes_left_to_write, ptr to amount_written]
        (i32.load) ;; stack: [bytes_left_to_write, amount_written]
        (i32.sub) ;; stack: [bytes_left_to_write - amount_written]
        (local.set $bytes_left_to_write) ;; stack: []

        (br $body_write_loop)))

    ;; ... and that's it. I thought I needed to call the close() function on
    ;; the body, but it turns out that doing so invalidates the handle and
    ;; means we can't send it in send_response. So ... just return here.
    (return))

  ;; Load the request information into the appropriate handle, so that
  ;; we can interact with it in the future.
  (func $load_request
      (global.get $request_handle_buffer)
      (global.get $request_body_buffer)
      (call $request_get)
      (call $maybe_error_die)
    )

  ;; get the size the user wants from the provided header
  ;; we're going to cheat a bit, here, and assume that the only
  ;; reason we might get an error is because the user didn't pass
  ;; this header. so if they didn't pass a header, or really if any
  ;; other error happens looking up the field value, we're going to
  ;; just return zero.
  (func $get_size (param $string_ptr i32) (result i32)
     (block $test_block
       ;; first, let's get the string for this header
       (global.get $request_handle_buffer)
       (i32.load)
       (local.get $string_ptr)
       (local.get $string_ptr) ;; \ These put the string length on the
       (call $strlen)          ;; / stack next.
       (global.get $message) ;; output buffer; leave 4 bytes for length
       (global.get $message_max_len) ;; output buffer length; leave 4 bytes for length
       (global.get $message_length) ;; here's the amount written, which we left space for
       (call $header_get)
       (i32.const 0) ;; if the value on the stack (the return code from
       (i32.eq)      ;; header_get) is equal to 0
       (br_if $test_block) ;; then break out of this block

       ;; assume that we should default to 0.
       (i32.const 0) ;; otherwise, return 0
       (return))

     ;; now we need to turn the darn ASCII string into a number
     (global.get $message)
     (global.get $message_length) ;; this is the message length ptr
     (i32.load) ;; get the actual length
     (call $to_int))


  ;; Send OK back to the test harness; this thing is exitting normally
  (func $send_response (param $result i32)
      ;; set the status
      (global.get $response_handle_buffer)
      (i32.load)
      (local.get $result)
      (call $response_set_status)
      (call $maybe_error_die)

      ;; send it to the client
      (global.get $response_handle_buffer)
      (i32.load)
      (global.get $response_body_buffer)
      (i32.load)
      (i32.const 0) ;; not streaming
      (call $response_send)
      (call $maybe_error_die)
    )

  ;; Convert the given ASCII string into an integer. This function does
  ;; no safety checking, so SHOULD NOT BE USED IN PRODUCTION! ALARM
  ;; ALARM ALARM!
  (func $to_int (param $str i32) (param $len i32) (result i32)
    (local $result i32)
    (local $offset i32)

    (i32.const 0)
    (local.set $result) ;; result = 0
    (i32.const 0)
    (local.set $offset) ;; offset = 0

    (loop $loop_body
      ;; if offset >= len then break. this feels a little awkward, but
      ;; it's how I got break to work. recall that in WAT, if the test
      ;; is true and you `br_if` to a `block` label, then it pops you
      ;; out of that label. so, in this case, if the offset is less
      ;; than the length, then we pop out of $maybe_done. if it's >=,
      ;; then we keep going ... which just fetches the results and
      ;; returns.
      (block $maybe_done
        (local.get $offset)
        (local.get $len)
        (i32.lt_u)
        (br_if $maybe_done)
        (local.get $result)
        (return))

      ;; compute the next address in the string; $str + $offset
      (local.get $str)
      (local.get $offset)
      (i32.add)

      ;; read the next character, and turn it into a value by
      ;; subtracting off the ASCII value of '0'; ASCII values
      ;; are helpfully in order, so this gets us a numerical
      ;; value from an ASCII one.
      (i32.load8_u)
      (i32.const 48) ;; ASCII '0' == 48
      (i32.sub)

      ;; Multiply the previous result by 10, then add the new
      ;; value. The new value is on the stack from the sub.
      (local.get $result)
      (i32.const 10)
      (i32.mul)
      (i32.add)

      ;; set the new result, and increment the offset
      (local.set $result)
      (local.get $offset)
      (i32.const 1)
      (i32.add)
      (local.set $offset)
      
      ;; repeat!
      (br $loop_body))

    unreachable)

  ;; convert the provided integer into a string, storing the values into
  ;; memory at the given offset, and returning a new offset (where, presumably
  ;; one could write more data).
  ;;
  ;; this is implemented as a recursive function, which is a bit scary
  ;; but turns out to be not that bad.
  (func $int2str (param $i i32) (param $offset i32) (result i32)
    ;; OK, check for our base case: is $i less than 10. if it is, then
    ;; we're just going to write our single character and return.
    (block $base_case_exit
      (local.get $i)
      (i32.const 10)
      (i32.ge_u)
      (br_if $base_case_exit) ;; oh, well

      ;; yay! this is a number less than 10, which is pretty easy to
      ;; convert using knowledge of the ASCII table. ASCII '0' is 48,
      ;; so we just need to add $i to 46, write that value to our
      ;; offset, and return $offset + 1.
      (local.get $offset) ;; this is where to write it
      (i32.const 48)
      (local.get $i)
      (i32.add) ;; now we have the ASCII character
      (i32.store8) ;; written!

      ;; bump the offset and return
      (local.get $offset)
      (i32.const 1)
      (i32.add)
      (return))

    ;; OK! we're bigger than 10. we're going to recursively call this
    ;; function twice. First, with $i / 10, and then with $i % 10.
    (local.get $i)
    (i32.const 10)
    (i32.div_u) ;; this puts the new i value for the first call on the stack
    (local.get $offset) ;; conveniently, we just want to put it in the same place
    (call $int2str)

    ;; when we get back, the top of the stack is our new offset, which we
    ;; will immediately save.
    (local.set $offset)
    ;; now compute $i % 10
    (local.get $i)
    (i32.const 10)
    (i32.rem_u) ;; puts the new i on the stack
    (local.get $offset) ;; ... which we just saved
    (call $int2str)

    ;; and this call will put the new offset on the stack ... which is
    ;; what we wanted to return, so just return.
    (return))

  ;; compute the length of a NULL-terminated string. if this is not a
  ;; NULL-terminated string, you're going to have a bad day.
  (func $strlen (param $str i32) (result i32)
    (local $offset i32)

    ;; start at 0
    (i32.const 0)
    (local.set $offset) ;; offset = 0

    (loop $loop_body

      (block $maybe_done
        ;; compute the pointer we're going to use here
        (local.get $str)
        (local.get $offset)
        (i32.add)
        (i32.load8_u)

        ;; if it's zero, return the current offset, which happens to
        ;; also be the length.
        (i32.const 0)
        (i32.ne)
        (br_if $maybe_done)
        (local.get $offset)
        (return))

      ;; increment the offset
      (local.get $offset)
      (i32.const 1)
      (i32.add)
      (local.set $offset)
      
      ;; repeat!
      (br $loop_body))

    unreachable)

  (func $wait_until (param $target i64)
    (loop $uffish_thought
      (i32.const 1) ;; we're looking for the monotonic clock
      (i64.const 1000000000) ;; a precision of 1 second is just fine
      (global.get $loop_time_response)
      (call $what_time_is_it)
      (call $maybe_error_die)

      (local.get $target)
      (global.get $loop_time_response)
      (i64.load)
      (i64.gt_u)
      (br_if $uffish_thought)))

  ;; this is not super informative, but: check to see if the status code
  ;; from whatever hostcall we just invoked came back as OK (0); if not,
  ;; immediately exit with the return value as a diagnostic. (Not that it
  ;; tells us where that value came from, but at least it's something?)
  (func $maybe_error_die (param $status_code i32)
    (block $test_block
      (local.get $status_code)
      (i32.const 0)
      (i32.ne)
      (br_if $test_block)
      (return)
    )
    (local.get $status_code)
    (call $wasi_exit)
    unreachable
    )

  (memory (;0;) 1) ;; 1 * 64k = 64k :)
  (export "memory" (memory 0))

  ;; we're going to use the lowest 4k for globals and such, and then put
  ;; a bunch of strings right after, spread 128 bytes apart.
  (data $_header_guest_kb (i32.const 4096) "guest-kb\00")
  (data $_header_body_kb (i32.const 4224) "body-kb\00")
  (data $_header_header_kb (i32.const 4352) "header-kb\00")
  (data $_header_seconds_to_take (i32.const 4480) "seconds-to-take\00")
  (data $_lorem_ipsum (i32.const 4608) "Lorem ipsum dolor sit amet, consectetur adipiscing elit viverra.\00")
                                     ;; 1234567890123456789012345678901234567890123456789012345678901234
                                     ;; 0         1         2         3         4         5         6
  (data $_response_header_name (i32.const 4736) "x-test-header-")
                                              ;; 012345678901234
                                              ;;           1
  )