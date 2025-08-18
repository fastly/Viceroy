#!/bin/bash

cleanup() {
  kill $SERVER_PID
  wait $SERVER_PID 2>/dev/null
  echo "Server shuts down"
  exit 0
}

target/debug/switch-mm $1.wasm -o $1.shifted.wasm
#~/src/bytecodealliance/wasm-tools/target/debug/wasm-tools component new $1.shifted.wasm --adapt wasi_snapshot_preview1=/Users/chenyan/src/fastly/Viceroy/lib/data/viceroy-component-adapter.wasm -o composed.wasm
~/src/fastly/Viceroy/target/debug/viceroy adapt $1.shifted.wasm -o composed.wasm
~/src/fastly/Viceroy/target/debug/viceroy composed.wasm &
#~/src/fastly/Viceroy/target/debug/viceroy --adapt $1.shifted.wasm &
SERVER_PID=$!
sleep 1

if nc -z localhost 7676; then
  curl localhost:7676
else
  echo "server not ready"
  cleanup
fi

cleanup
