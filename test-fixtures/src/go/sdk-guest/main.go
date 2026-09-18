// Regression fixture for https://github.com/fastly/Viceroy/issues/491 (TinyGo) and
// https://github.com/fastly/Viceroy/issues/498 ("big" Go).
//
// Fixed by 92a76f4 (https://github.com/fastly/Viceroy/pull/538)
//
// Scenarios by request path:
//
//	/          hello world, proves the Fastly ABI round-trips at all
//	/gc        allocates enough to drive several GC cycles, then checksums it
//	/random    reads from crypto/rand, the path that used to trap in the adapter
//	/echo      echoes the request body back, exercising guest-owned buffers
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/fastly/compute-sdk-go/fsthttp"
)

func main() {
	fsthttp.ServeFunc(func(ctx context.Context, w fsthttp.ResponseWriter, r *fsthttp.Request) {
		switch r.URL.Path {
		case "/":
			w.WriteHeader(fsthttp.StatusOK)
			fmt.Fprintln(w, "Hello, Viceroy!")

		case "/gc":
			// Allocate well past the initial heap so the collector has to run
			// and the runtime has to grow linear memory. Under the original bug
			// this is what walked over the adapter's `State`.
			const (
				chunks    = 512
				chunkSize = 16 << 10
			)
			var sum uint64
			for i := range chunks {
				buf := make([]byte, chunkSize)
				for j := range buf {
					buf[j] = byte(i + j)
				}
				for _, b := range buf {
					sum += uint64(b)
				}
			}
			w.WriteHeader(fsthttp.StatusOK)
			fmt.Fprintf(w, "checksum %d\n", sum)

		case "/random":
			buf := make([]byte, 32)
			if _, err := rand.Read(buf); err != nil {
				w.WriteHeader(fsthttp.StatusInternalServerError)
				fmt.Fprintf(w, "rand.Read: %v\n", err)
				return
			}
			w.WriteHeader(fsthttp.StatusOK)
			fmt.Fprintln(w, hex.EncodeToString(buf))

		case "/echo":
			body, err := io.ReadAll(r.Body)
			if err != nil {
				w.WriteHeader(fsthttp.StatusInternalServerError)
				fmt.Fprintf(w, "read body: %v\n", err)
				return
			}
			w.WriteHeader(fsthttp.StatusOK)
			w.Write(body)

		default:
			w.WriteHeader(fsthttp.StatusNotFound)
			fmt.Fprintf(w, "no scenario for %s\n", r.URL.Path)
		}
	})
}
