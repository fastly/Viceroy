(module
  (import "fastly_http_resp" "new"
    (func $response_new
      (param i32)
      (result i32)))
  (import "fastly_http_body" "new"
    (func $body_new
      (param i32)
      (result i32)))
  (import "fastly_http_resp" "status_set"
    (func $response_set_status
      (param i32) (param i32)
      (result i32)))
  (import "fastly_http_resp" "send_downstream"
    (func $response_send
      (param i32) (param i32) (param i32)
      (result i32)))
 
  (import "wasi_snapshot_preview1" "proc_exit"
    (func $wasi_exit
      (param i32)))

  ;; we're going to fix a few memory locations as constants, just to avoid
  ;; some other messiness, even though it's bad software engineering.
  (global $response_handle_buffer i32 (i32.const 4))
  (global $body_handle_buffer i32 (i32.const 8))

  (func $main (export "_start")
    (i32.const 200)
    (call $send_response)
    (i32.const 0)
    (call $wasi_exit)
    unreachable
    )

  ;; Send a resposne back to the test harness, using the status code
  ;; provided in the first argument. This message will have no body,
  ;; and no headers, just the response code. It will fail catastrophically
  ;; (i.e., end this execution) if anything goes wrong in the process.
  (func $send_response (param $result i32)
      ;; create the response
      (global.get $response_handle_buffer)
      (call $response_new)
      (call $maybe_error_die)

      ;; create an empty body
      (global.get $body_handle_buffer)
      (call $body_new)
      (call $maybe_error_die)

      ;; set the status
      (global.get $response_handle_buffer)
      (i32.load)
      (local.get $result)
      (call $response_set_status)
      (call $maybe_error_die)

      ;; send it to the client
      (global.get $response_handle_buffer)
      (i32.load)

      ;; empty body
      (global.get $body_handle_buffer)
      (i32.load)

      (i32.const 0) ;; not streaming
      (call $response_send)
      (call $maybe_error_die)
    )

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

  )