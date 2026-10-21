// Regression fixture for https://github.com/fastly/Viceroy/issues/491 (TinyGo) and
// https://github.com/fastly/Viceroy/issues/498 ("big" Go).
//
// Previously, the component adapter would make space for its own state by growing
// the guest's memory during instantiation. This worked under Rust guests, but neither
// Go runtime respects it. On startup, the go runtime writes over the adapter's pages,
// and the first hostcall fails the adapter's magic-number check.
//
// Fixed by shifting the main module's memory accesses so the adapter owns the first
// pages. See 92a76f4 (https://github.com/fastly/Viceroy/pull/538).
package main

import (
	"context"

	"github.com/fastly/compute-sdk-go/fsthttp"
)

func main() {
	fsthttp.ServeFunc(func(ctx context.Context, w fsthttp.ResponseWriter, r *fsthttp.Request) {})
}
