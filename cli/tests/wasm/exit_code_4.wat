(module
  (import "wasi_snapshot_preview1" "proc_exit"
  (func $proc_exit (param i32)))
  (export "_start" (func $_start))
  (memory 10)
  (export "memory" (memory 0))

  (func $_start
    (call $proc_exit (i32.const 4))
  )
)